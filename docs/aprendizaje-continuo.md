# Aprendizaje Continuo Seguro

El sistema aprende de nuevas amenazas de forma **continua, segura y verificable**, sin depender solo
de firmas y **sin permitir que un atacante "enseñe" comportamientos maliciosos como normales**
(*data poisoning* / *model evasion*). El principio rector: **el aprendizaje ocurre en la nube, con
validación en varias etapas, y solo se promueve conocimiento firmado y probado al endpoint.**

---

## 1. Pipeline MLOps de extremo a extremo

```
  Endpoints (telemetría/muestras, con consentimiento)
        │
        ▼
  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   ┌──────────────┐
  │ Ingesta     │──►│ Sandbox +    │──►│ Etiquetado      │──►│ Feature Store │
  │ (Kafka)     │   │ análisis     │   │ (auto + humano) │   │ (Feast)       │
  └─────────────┘   └──────────────┘   └─────────────────┘   └──────┬───────┘
                                                                     │
   ┌───────────────────────────────────────────────────────────────┘
   ▼
  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   ┌──────────────┐
  │ Entrenamiento│─►│ Validación    │─►│ Model Registry  │─►│ Despliegue    │
  │ / reentreno  │  │ (holdout,     │  │ (versionado,    │  │ CANARIO +     │
  │              │  │  adversarial, │  │  firmado)       │  │ rollback auto │
  │              │  │  FP/FN gates) │  │                 │  │               │
  └──────────────┘  └──────────────┘  └─────────────────┘  └──────┬───────┘
                                                                   │ firmado (TUF)
                                                                   ▼
                                                            Endpoints (inferencia)
```

Herramientas: Kubeflow/MLflow (orquestación y registro), Feast (feature store), DVC/Delta Lake
(versionado de datos), y *gates* automáticos de calidad en CI/CD de modelos.

---

## 2. Fuentes de aprendizaje

1. **Muestras nuevas del campo** — ficheros/eventos sospechosos que los endpoints envían **con
   consentimiento** y anonimización. Se detonan en sandbox para etiquetado automático.
2. **Threat intelligence externa** — feeds STIX/TAXII, comerciales, OSINT, VirusTotal-like,
   honeypots propios. Normalizados a IoCs.
3. **Telemetría agregada** — prevalencia, patrones de comportamiento, líneas base para anomalías.
4. **Retroalimentación del SOC/analistas** — etiquetas de alta calidad, resolución de FP/FN
   reportados por clientes.
5. **Red-team interno** — generación controlada de variantes/adversariales para robustecer los
   modelos.

---

## 3. Actualización segura de modelos

- **Todo modelo se firma** (Ed25519) y se distribuye vía **TUF** (resistente a compromiso de la
  infraestructura de distribución) con **anti-rollback** (versionado monotónico).
- **Despliegue canario:** el nuevo modelo va primero a un pequeño % de la flota. Se vigilan FP, FN,
  latencia y estabilidad. Solo si supera los umbrales se promueve globalmente; si degrada,
  **rollback automático**.
- **Shadow mode:** el modelo candidato corre en paralelo al de producción (sin actuar) para comparar
  veredictos antes de activarlo.
- **Reproducibilidad:** cada modelo registra datos, features, hiperparámetros y código (linaje
  completo) para auditoría y rollback exacto.

> **Decisión clave:** el endpoint **no** reentrena con datos locales no validados. Recibe modelos ya
> entrenados y validados en la nube. Esto cierra el vector de envenenamiento local.

---

## 4. Defensa contra envenenamiento (data poisoning) y ataques adversariales

Este es el requisito crítico: **impedir que atacantes enseñen al sistema que lo malicioso es normal.**

### 4.1 Contra envenenamiento de datos de entrenamiento

1. **No confianza automática en el campo.** Ninguna muestra del endpoint se convierte en etiqueta de
   entrenamiento directamente. Pasa por sandbox + verificación + (para casos dudosos) revisión humana.
2. **Procedencia y reputación del emisor.** Se pondera la fiabilidad de la fuente; muestras de
   dispositivos con comportamiento anómalo o de baja reputación se aíslan/descartan.
3. **Detección de anomalías en el dataset.** Antes de entrenar, se buscan *clusters* sospechosos de
   etiquetas coordinadas (posible campaña de envenenamiento) — defensa tipo *influence functions* /
   *activation clustering* / detección de outliers.
4. **Etiquetado por consenso.** Se requiere concordancia entre múltiples señales (sandbox + varios
   feeds + prevalencia) para una etiqueta de "limpio", especialmente para evitar que un atacante
   marque su malware como benigno.
5. **Límites de influencia.** Ninguna fuente o dispositivo individual puede mover el modelo por encima
   de un umbral (rate-limiting de influencia, *robust aggregation*).
6. **Canary/holdout envenenado.** Sets de validación curados y secretos: si un reentrenamiento degrada
   la detección sobre malware conocido (señal de envenenamiento), se bloquea la promoción.

### 4.2 Contra ataques adversariales al modelo (evasión)

1. **Entrenamiento adversarial** — se incluyen ejemplos perturbados/empaquetados para robustecer.
2. **Ensembles y diversidad** — combinar modelos y técnicas (firmas + comportamiento + reputación)
   hace que evadir uno no baste; el comportamiento en runtime es difícil de falsificar.
3. **Ofuscación/rotación del modelo** — no exponer el modelo; rotar versiones para dificultar el
   *model stealing* y la construcción de evasiones estables.
4. **Detección de consultas de sondeo** — patrones de *probing* (muchas variantes marginales) se
   detectan como reconocimiento adversarial.
5. **Defensa en profundidad** — la decisión final nunca depende de un solo modelo; el runtime
   behavioral y el sandbox son la red de seguridad contra evasiones estáticas.

### 4.3 Validación antes de incorporar conocimiento (gate de promoción)

Un modelo/regla **solo se promueve** si pasa TODAS estas puertas:

- [x] Precisión/recall ≥ umbrales sobre holdout curado y secreto.
- [x] Tasa de FP ≤ umbral sobre un corpus grande de software **limpio y prevalente** (clean set).
- [x] No degradación sobre el set de regresión de malware conocido.
- [x] Robustez adversarial ≥ umbral.
- [x] Estabilidad en *shadow mode* y canario.
- [x] Revisión humana (SOC) para cambios significativos.
- [x] Firma criptográfica y registro de linaje.

---

## 5. Inteligencia de amenazas desde la nube al endpoint

- El endpoint recibe **paquetes firmados** de: firmas/IoCs (frecuente), reglas de comportamiento
  (diario/urgente) y modelos (periódico/canario).
- Push urgente (*emergency signature*) para brotes activos (p. ej. ransomware en propagación), con
  el mismo control de firma pero cadencia inmediata.
- El endpoint **contribuye de vuelta** (telemetría/muestras con consentimiento) cerrando el bucle de
  *inteligencia colectiva*: cuanto mayor la base instalada, mejor y más rápida la protección para
  todos.

---

## 6. Ética, privacidad y cumplimiento

- **Minimización de datos:** por defecto se envían **metadatos y hashes**, no contenido de ficheros.
  La subida de una muestra completa requiere **consentimiento explícito** (o política empresarial) y
  se aplica *scrubbing* de datos personales.
- **Anonimización/seudonimización** de la telemetría; retención limitada y con propósito.
- **Cumplimiento** GDPR/CCPA/HIPAA (según segmento): base legal, DPA, derecho de acceso/borrado,
  residencia de datos (multi-región).
- **Transparencia:** documentación clara de qué se recopila y por qué; controles para el usuario.
- **Uso ético del modelo:** el sistema se diseña para **defensa**; los datos no se usan para fines
  ajenos a la seguridad.
