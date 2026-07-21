# Motor de Detección Híbrido

El motor combina **ocho técnicas complementarias** siguiendo el principio de **defensa en
profundidad**: ninguna técnica es suficiente por sí sola, pero su combinación ponderada maximiza la
detección (incluido zero-day) y minimiza los falsos positivos. Un **motor de decisión** (scoring
engine) consolida los veredictos parciales.

---

## 1. Arquitectura del motor

```
                        ┌─────────────────────────────────────┐
   Evento / Fichero ───►│           PRE-FILTRO / TRIAGE        │
   (kernel, on-access)  │  (allowlist, Bloom filter, tipo)     │
                        └───────────────┬─────────────────────┘
                                        │ (solo lo no confiable)
        ┌───────────────┬───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼               ▼
   ┌─────────┐   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
   │ Firmas  │   │ Heurística │  │ ML estático│  │ Reputación │  │ Anomalías  │
   └────┬────┘   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
        │              │               │               │              │
        └──────────────┴───────┬───────┴───────────────┴──────────────┘
                               ▼
                    ┌─────────────────────┐        ┌──────────────────────┐
                    │  MOTOR DE DECISIÓN   │◄───────│ Detección por         │
                    │  (scoring ponderado, │        │ comportamiento (runtime)│
                    │   fusión de señales) │        └──────────────────────┘
                    └──────────┬───────────┘                 ▲
                               │                             │ (si sigue incierto)
                    ┌──────────▼───────────┐        ┌────────┴─────────┐
                    │  Veredicto:          │───────►│  Sandbox (nube)  │
                    │  limpio / sospechoso │        │  detonación      │
                    │  / malicioso         │        └──────────────────┘
                    └──────────────────────┘
```

El motor de decisión asigna **pesos** por técnica y por contexto (tipo de fichero, origen, nivel de
confianza del usuario/política). Puede operar en modos: *balanceado*, *agresivo* (más heurística) y
*silencioso* (menos intervención). Usa un **meta-modelo** (stacking) entrenado para combinar señales y
calibrar la probabilidad final, con umbrales ajustables por política.

---

## 2. Las ocho técnicas: ventajas y limitaciones

### 2.1 Firmas tradicionales

**Cómo funciona:** compara hashes (SHA-256), *fuzzy hashes* (ssdeep/TLSH) y patrones de bytes (reglas
YARA) contra una base de amenazas conocidas.

- **Ventajas:** rapidísima, determinista, cero (o casi cero) falsos positivos, bajo consumo, ideal
  para bloquear amenazas conocidas en masa. Explicable.
- **Limitaciones:** **inútil frente a malware nuevo/polimórfico/empaquetado**; requiere actualización
  constante; los atacantes evaden con cambios triviales. El *fuzzy hashing* mitiga parcialmente el
  polimorfismo.
- **Rol en el híbrido:** primera línea barata; descarta amenazas conocidas antes de gastar cómputo en
  técnicas caras.

### 2.2 Heurística

**Cómo funciona:** reglas expertas sobre características estáticas sospechosas (entropía alta =
empaquetado/cifrado, importaciones peligrosas, secciones anómalas del PE, *strings* sospechosos,
código automodificable).

- **Ventajas:** detecta variantes y familias sin firma exacta; explicable; barata.
- **Limitaciones:** **más falsos positivos** que las firmas; requiere ajuste experto continuo; los
  atacantes que conocen las reglas las evaden. Mantenimiento intensivo.
- **Rol:** puente entre firmas y ML; captura patrones conocidos de "maldad" estructural.

### 2.3 Detección por comportamiento (runtime / dinámica)

**Cómo funciona:** monitoriza acciones en ejecución vía los drivers de kernel: llamadas al sistema,
creación de procesos, inyección, hooking, acceso masivo a ficheros, modificación de arranque,
persistencia, tráfico C2. Correlaciona secuencias (p. ej. cadena de ataque tipo ATT&CK).

- **Ventajas:** **detecta malware desconocido y fileless** por lo que *hace*, no por lo que *es*;
  eficaz contra polimórficos y *living-off-the-land*. Núcleo de la protección **anti-ransomware**
  (detecta patrón de cifrado masivo + borrado de *shadow copies* y **revierte** cambios).
- **Limitaciones:** la amenaza **ya se está ejecutando** (hay que actuar rápido y poder revertir);
  coste de rendimiento por monitorización; posibles FP con software legítimo agresivo (backups,
  cifradores). Requiere *rollback* transaccional para ser seguro.
- **Rol:** capa decisiva para zero-day y ransomware. Se combina con *canary files* (señuelos) y
  *rollback* de E/S.

### 2.4 Machine Learning (estático)

**Cómo funciona:** modelos (gradient boosting como LightGBM/XGBoost, y redes para *raw bytes* tipo
MalConv/CNN) que clasifican ficheros a partir de cientos de *features* (cabeceras PE, entropía,
n-gramas de opcodes, imports, metadatos).

- **Ventajas:** **generaliza a malware nunca visto**; detecta familias completas; inferencia rápida en
  el endpoint (ONNX). Escala mejor que reglas manuales.
- **Limitaciones:** requiere datos de entrenamiento masivos y bien etiquetados; **vulnerable a
  ataques adversariales** (perturbaciones que evaden el modelo); riesgo de FP; *drift* del modelo con
  el tiempo; menos explicable (mitigable con SHAP). Puede degradarse si el atacante conoce el modelo.
- **Rol:** motor principal de detección de "lo desconocido" en estático, complementado con
  explicabilidad y reentrenamiento continuo.

### 2.5 Modelos de IA (avanzados)

**Cómo funciona:** modelos más ricos para tareas específicas: análisis de secuencias de comportamiento
(Transformers/LSTM sobre trazas de API), *graph neural networks* sobre grafos de llamadas/procesos, y
LLMs especializados para analizar scripts (PowerShell/JS ofuscados), macros y correlación de
incidentes. Detección de spyware/keyloggers por patrones de *hooking* de entrada y exfiltración.

- **Ventajas:** capturan **relaciones complejas y temporales** que el ML clásico no ve; excelentes
  para desofuscar scripts y detectar campañas; útiles para el analista (triage asistido).
- **Limitaciones:** **coste computacional alto** (mejor en la nube/sandbox, no en el endpoint por
  defecto); latencia; posibles alucinaciones si se usan LLMs sin restricción; necesidad de
  verificación. No deben ser el único árbitro.
- **Rol:** análisis profundo en nube/sandbox y asistencia al SOC; sus conclusiones alimentan firmas y
  reglas que sí bajan al endpoint.

### 2.6 Detección de anomalías

**Cómo funciona:** modela la *línea base* de comportamiento normal de cada host/usuario (procesos
habituales, conexiones, uso de recursos) con métodos no supervisados (Isolation Forest, autoencoders,
clustering) y alerta ante desviaciones.

- **Ventajas:** detecta amenazas **sin ejemplos previos** (insider, APT sigilosa, spyware silencioso);
  se adapta a cada entorno.
- **Limitaciones:** **falsos positivos** si la línea base es ruidosa o cambia (nuevo software); coste
  de perfilado; ventana de aprendizaje inicial; los atacantes "lentos y sigilosos" pueden mezclarse
  con el ruido.
- **Rol:** capa de red de seguridad para lo que las demás no ven; especialmente útil en EDR/empresa.

### 2.7 Análisis de reputación

**Cómo funciona:** consulta a la nube la reputación de ficheros (hash), URLs, dominios, IPs y
certificados de firma, basada en prevalencia global, antigüedad, origen y observaciones previas
("visto en 5 M de máquinas durante 2 años, firmado por X" = confiable; "visto por primera vez hace
1 h, sin firma" = sospechoso).

- **Ventajas:** **inteligencia colectiva**; muy eficaz contra *droppers* nuevos y *phishing*; barata
  en el cliente (una consulta); reduce FP al confirmar software legítimo prevalente.
- **Limitaciones:** requiere conectividad (mitigado con caché local); ventana ciega para lo
  verdaderamente nuevo hasta que gana prevalencia; privacidad (se envían hashes/URLs, no contenido);
  posible envenenamiento de reputación (mitigado con detección de manipulación).
- **Rol:** desempate y reducción de FP; enriquece a todas las demás capas.

### 2.8 Sandbox aislado

**Cómo funciona:** ejecuta (*detona*) el fichero sospechoso en un entorno **aislado** (microVM
Firecracker / VM con instrumentación) y observa su comportamiento real, extrayendo IoCs y un veredicto.

- **Ventajas:** **máxima visibilidad** del comportamiento real; genera firmas y reglas nuevas
  automáticamente; ideal para lo desconocido de alto riesgo. Aísla el riesgo.
- **Limitaciones:** **lento y caro** (segundos-minutos) → no apto para escaneo on-access en tiempo
  real; el malware **evade sandbox** (detección de VM, retardos, *triggers* por interacción);
  cobertura de rutas limitada. Se ejecuta en la nube, no en el endpoint.
- **Rol:** análisis definitivo de muestras sospechosas y desconocidas; retroalimenta firmas, ML y
  reputación. Se combina con anti-evasión (ocultar artefactos de VM, simular interacción, acelerar
  reloj).

---

## 3. Motor de decisión (fusión de señales)

- **Entrada:** vector de veredictos y confianzas de cada capa + contexto (tipo, origen, prevalencia,
  política).
- **Método:** *stacking* (meta-modelo calibrado) + reglas de veto duro (una firma confirmada bloquea;
  un allowlist firmado exime). Salida: `limpio | sospechoso | malicioso` con probabilidad y
  **explicación** (qué señales pesaron).
- **Umbrales por política:** empresas pueden endurecer (más bloqueo) o relajar (menos fricción).
- **Acciones graduadas:** monitorizar → alertar → bloquear/matar proceso → poner en cuarentena →
  revertir cambios → aislar host.
- **Minimización de FP:** doble confirmación para acciones destructivas, allowlisting de software
  prevalente/firmado, *soft-block* reversible antes de acciones irreversibles, y bucle de feedback con
  el pipeline de aprendizaje.

---

## 4. Flujo específico anti-ransomware (ejemplo)

1. Detección por comportamiento observa: enumeración masiva de ficheros + escrituras con alta entropía
   + intento de borrar *Volume Shadow Copies*.
2. Se activan *canary files* (señuelos monitorizados) → cualquier modificación es señal fuerte.
3. El motor de decisión sube el score; **se suspende el proceso** de inmediato (no matar aún, para
   permitir análisis y evitar corrupción).
4. Se **revierten** los cambios usando el journal de E/S / copias protegidas.
5. Se pone en cuarentena, se genera IoC y se envía (con consentimiento) a la nube para firma global.

Este flujo detecta ransomware **antes de que complete el cifrado**, que es el objetivo del requisito.
