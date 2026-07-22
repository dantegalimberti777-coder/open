# Etapa 2 — Motor de análisis de comportamiento (núcleo)

> Estado: **núcleo implementado y validado** (6 tests). El **sensor** que alimenta
> eventos reales (ETW en Windows / eBPF en Linux) es el siguiente sub-paso.

Detecta técnicas modernas de malware **por lo que un proceso hace**, no por
firmas: inyección de código, *process hollowing*, inyección APC, carga
reflexiva, acceso a credenciales, evasión de defensas, LOLBins/LotL, borrado de
*shadow copies* y cifrado masivo (ransomware), persistencia (registro, tareas,
WMI, servicios, drivers), keylogging, C2 y exfiltración.

## 1. Diseño

- **Entrada:** flujo de `SystemEvent` abstractos. Cada evento trae uno o más
  `Indicator` (categorías ligadas a **MITRE ATT&CK**) que el **sensor** asignó a
  partir de la actividad real del sistema.
- **Acumulación por proceso:** el motor mantiene el conjunto de indicadores
  distintos vistos por PID (y su árbol).
- **Fusión de riesgo (noisy-OR):** `score = 1 − ∏(1 − wᵢ)`. Varios indicadores
  débiles **escalan** el riesgo, pero **ninguno solo** llega al máximo → cumple
  el requisito "la decisión nunca depende de una sola técnica".
- **Umbrales por política:** sospechoso ≥ 0.45, malicioso ≥ 0.75 (configurable).
- **Explicabilidad:** cada alerta genera un informe legible con las técnicas
  ATT&CK detectadas y la puntuación ("por qué es peligroso").

### Ejemplo real (salida de `ngav behavior-demo`)

```
Paso 1: reserva memoria y escribe en otro proceso     riesgo 0.40
Paso 2: crea un hilo remoto en el proceso objetivo     riesgo 0.40
Paso 3: lee la memoria del subsistema de credenciales  riesgo 0.70  SOSPECHOSO
Paso 4: intenta desactivar la protección               riesgo 0.83  MALICIOSO

[ALERTA] Proceso 4242 — MALICIOSO (0.83)
  • [T1055] inyección de código en otro proceso
  • [T1003] acceso a credenciales del sistema
  • [T1562] intento de desactivar defensas de seguridad
```

## 2. Decisión anti-falso-positivo (clave)

El núcleo usa **categorías abstractas** (`enum Indicator`), **no** nombres de
herramientas ni de APIs de Windows en texto plano. Así el binario **no contiene
cadenas** que otros antivirus marquen (lección directa de la Etapa 1/02). El
mapeo concreto «API/proceso real → indicador» lo hará el **sensor** de cada
plataforma, de forma *data-driven*, fuera de este núcleo.

## 3. SOLID / testabilidad

- El motor **no conoce el sistema operativo**: consume eventos abstractos, por lo
  que se prueba al 100% con secuencias sintéticas (6 tests: escalado de inyección,
  patrón ransomware, no-doble-conteo, monotonía y cota de noisy-OR, olvido de
  estado, indicador débil aislado).
- Preparado para conectarse al `RealtimeService` (Etapa 1) sin cambios
  estructurales: el servicio de tiempo real dispatchará estos eventos.

## 4. API pública

- `Indicator` (enum, con `weight()`, `mitre()`, `describe()`).
- `SystemEvent { pid, ppid, indicators, detail }`.
- `BehaviorEngine::observe(&event) -> Option<RiskAlert>`.
- `RiskAlert { pid, score, level, indicators, explanation }`.
- `explain(indicators, score, level) -> String` (informe legible).

## 5. Limitaciones y siguiente sub-paso

- Hoy el motor está **implementado y probado**, pero **aún no recibe eventos
  reales**: falta el **sensor**.
  - **Windows:** ETW (Event Tracing for Windows) + API nativa Toolhelp32 para
    procesos, **sin lanzar `powershell`/`cmd`** (requisito anti-Defender).
  - **Linux:** eBPF / `/proc` + auditd.
- El sensor traduce actividad real (p. ej. la secuencia
  reservar-memoria → escribir-en-proceso → hilo-remoto) al indicador
  `ProcessInjection`, etc. Ese mapeo es *data-driven* para no incrustar cadenas.
- Integración con la UI: nueva sección/entradas en la línea temporal cuando el
  sensor esté conectado.

## 6. Compatibilidad

Módulo nuevo y aislado (`behavior.rs`); no modifica ni reemplaza nada existente.
Se expone la demo `ngav behavior-demo` para verificarlo sin sensor.
