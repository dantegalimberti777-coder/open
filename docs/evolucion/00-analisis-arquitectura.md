# Análisis del proyecto y arquitectura de evolución a NGAV/XDR

> **Etapa 0 — Análisis y diseño (sin código).** Este documento audita el estado
> actual del proyecto, identifica fortalezas, debilidades, cuellos de botella y
> riesgos (seguridad, rendimiento, escalabilidad), y define la arquitectura
> objetivo y el plan por etapas para evolucionar a un NGAV/XDR de nivel
> comercial **manteniendo la compatibilidad con todo lo que ya funciona**.

Autor: equipo de ingeniería (arquitecto, ciberseguridad, IA, sistemas, DevOps).
Fecha: 2026-07-21. Estado del código auditado: rama `claude/nextgen-antivirus-ml-m0n2wq`.

---

## 1. Inventario auditado

| Área | Módulo | LoC | Rol |
|------|--------|-----|-----|
| Motor (Rust) | `hash.rs` | 208 | SHA-256 propio (streaming) |
| | `entropy.rs` | 53 | Entropía de Shannon (global) |
| | `signatures.rs` | 203 | Firmas hash + patrón de bytes (YARA-lite) |
| | `heuristics.rs` | 189 | Reglas estáticas por substring |
| | `reputation.rs` | 192 | Reputación local + cliente HTTP nube |
| | `decision.rs` | 218 | Fusión ponderada de señales → veredicto |
| | `engine.rs` | 208 | Orquestación por fichero |
| | `scanner.rs` | 255 | Escaneo incremental (índice) — **usado por CLI** |
| | `scanjob.rs` | 249 | Escaneo con progreso — **usado por GUI** |
| | `sysscan.rs` | 199 | Selección de rutas + enum. de procesos |
| | `quarantine.rs` | 214 | Aislamiento (ofuscación XOR) |
| | `updater.rs` | 89 | Descarga de firmas |
| | `licensing.rs` | 328 | Prueba 14 días + suscripción |
| | `config.rs` | 57 | Config y rutas |
| | `server.rs` | 677 | Servidor HTTP + API + orquestación |
| | `main.rs` | 385 | CLI |
| Nube (Go) | `cloud/reputation` | 356 | Reputación + canal de firmas |
| | `cloud/licensing` | 333 | Facturación (Stripe-ready) |
| UI | `ui/*` | 904 | SPA HTML/CSS/JS embebida |

**Cobertura de tests actual:** 47 unitarios (Rust) + tests de servicios (Go).
No hay integración, regresión, fuzzing, benchmark ni suite de seguridad.

---

## 2. Fortalezas reales (a preservar)

1. **Seam de detección correcto.** `Signal { source, score, reason, hard_block }`
   + `enum Source` + `decide()` es exactamente la base para un motor multicapa.
   El `enum Source` ya contempla `Behavior`, `Anomaly`, `MachineLearning` — sólo
   faltan los productores. **Este es el punto de extensión que reutilizaremos.**
2. **Puerto de reputación.** `trait ReputationSource` es un Port limpio
   (Dependency Inversion) con dos adaptadores (local/nube). Modelo a replicar.
3. **Rust en el núcleo privilegiado.** Decisión correcta para software de
   seguridad (seguridad de memoria). Se mantiene.
4. **Separación cliente/nube y degradación offline.** El endpoint funciona sin
   nube; la nube enriquece. Arquitectura correcta.
5. **Licenciamiento con gating funcional** y servicio Stripe-ready.
6. **Build reproducible a `.exe`** y empaquetado. CI básica con fmt+clippy+tests.
7. **Documentación técnica extensa** ya existente en `docs/`.

Ninguna de estas piezas se elimina ni se reescribe: se **envuelven** detrás de
puertos y se **extienden**.

---

## 3. Debilidades, cuellos de botella y riesgos (por dimensión)

### 3.1 Detección (lo que hoy impide competir)

- **Sólo 3 capas activas.** `engine.rs` sólo produce señales de Firmas,
  Heurística y Reputación. `Behavior`, `Anomaly`, `MachineLearning` están
  declaradas pero **no las produce nadie**. No hay: comportamiento en runtime,
  ML real, memoria, red, sandbox, YARA real, Sigma, parser PE.
- **Firmas no escalan.** El matching de patrones es substring naïve `O(n·m)` por
  patrón, iterando **todos** los patrones por fichero. Con miles de reglas es
  inviable. Falta Aho-Corasick / motor YARA real. La base es texto sin firmar.
- **Heurística cara.** Copia todo el fichero a minúsculas y hace `windows()` por
  cada uno de ~40 patrones. Sin parser PE (imports, secciones, entropía por
  sección): sólo `starts_with(b"MZ")`.
- **Fusión mejorable.** Media ponderada con pesos fijos puede **diluir** una
  señal fuerte; veto por `score >= 0.999` (comparación float frágil); la
  reputación "buena" no exime (no hay allowlist-veto); sin calibración ni pesos
  por contexto.
- **Sin tiempo real.** Sólo escaneos manuales/disparados. No hay vigilancia de
  creación/modificación/borrado/rename/ejecución de ficheros.

### 3.2 Seguridad del producto (crítico)

- **API local sin autenticación.** `server.rs` escucha en `127.0.0.1` pero
  **cualquier proceso local** puede `POST /api/quarantine/action` (¡restaurar un
  fichero malicioso!), `/api/scan`, `/api/license/activate`. Sin token de
  sesión, sin verificación de `Origin`/`Host` → expuesto a **CSRF / DNS
  rebinding** desde el navegador.
- **DoS trivial en el servidor HTTP propio.** Lee `Content-Length` arbitrario a
  memoria (sin tope), un hilo por conexión sin límite → agotamiento de recursos.
- **Transporte sin TLS ni firma.** Reputación, updater y licencias van por
  **HTTP plano**. Un MITM puede **inyectar firmas o un modelo envenenado**. TUF
  y firma Ed25519 están *diseñados* pero **no implementados**.
- **Licencia falsificable.** `license.txt` es texto plano editable
  (`status=active`); el token no está firmado. `validate_key` demo acepta
  cualquier prefijo `NGAV-`.
- **Cuarentena = ofuscación, no cifrado.** XOR (documentado honestamente). Falta
  cifrado autenticado (AES-GCM/ChaCha20-Poly1305).
- **Sin autoprotección (anti-tamper).** Nada impide matar el proceso, borrar sus
  ficheros o desactivarlo.
- **Parsing frágil.** JSON hecho a mano (`contains("\"verdict\":\"bad\"")`) es
  spoofable y propenso a errores de escape.

### 3.3 Rendimiento

- **Lecturas completas a memoria** (hasta 256 MB), sin `mmap`, sin SIMD.
- **Escaneo secuencial.** `scanjob` itera fichero a fichero **sin pool de
  hilos** (no aprovecha multinúcleo). No hay caché de veredicto por hash entre
  ejecuciones en la ruta GUI.
- **Reputación: una conexión TCP nueva por lookup** (`Connection: close`), sin
  pooling ni batch. Inviable para tiempo real.

### 3.4 Escalabilidad (nube)

- Reputación y licencias guardan estado **en memoria** (mapas), no durable, no
  escalable horizontalmente, sin base de datos. Correcto como MVP, no para
  millones de endpoints. Falta el diseño de datos (KV distribuido, colas, CDN).

### 3.5 Arquitectura y calidad de código

- **`server.rs` es un "God module"** (677 LoC): mezcla transporte HTTP, routing,
  serialización JSON y **lógica de negocio** (orquestación de escaneo, gating de
  licencia, threads). Viola SRP y Clean Architecture (la lógica de dominio
  depende del detalle HTTP).
- **Duplicación de escaneo.** `scanner.rs` (incremental, CLI) y `scanjob.rs`
  (progreso, GUI) son **dos caminos divergentes**; la GUI **perdió** el escaneo
  incremental. Viola DRY (y tu regla de "no duplicar").
- **Un solo crate.** Para crecer (comportamiento, memoria, red, ML, drivers) se
  necesita un **workspace Cargo multi-crate** con límites explícitos.
- **Errores ad-hoc** (`String`/`io::Error` mezclados), sin tipos de error de
  dominio, sin logging estructurado ni tracing.
- **Restricción "cero dependencias".** Fue correcta para garantizar compilación
  offline del MVP, pero es hoy **el mayor freno**: tiempo real eficiente, ETW,
  TLS, ONNX y async **requieren** crates especializados. Ver §5.

---

## 4. Arquitectura objetivo (Clean Architecture + Ports & Adapters)

Principio rector: **el dominio no depende de detalles**. HTTP, ETW, ONNX,
inotify, TLS, Stripe son *detalles* detrás de *puertos* (traits). Así cada nueva
capa (comportamiento, memoria, red, ML, sandbox) es un **adaptador enchufable**
sin tocar el resto — exactamente lo que ya hace `ReputationSource`.

### 4.1 Capas

```
┌───────────────────────────────────────────────────────────────────┐
│  ADAPTADORES / DETALLES (frameworks, SO, red)                      │
│  HTTP API · UI · ETW/inotify/ReadDirectoryChangesW · ONNX runtime  │
│  rustls/TLS · Stripe · WinAPI (drivers) · Sandbox · Kafka          │
└───────────────▲───────────────────────────────────────▲───────────┘
                │ (implementan puertos)                  │
┌───────────────┴───────────────────────────────────────┴───────────┐
│  APLICACIÓN (casos de uso, orquestación)                           │
│  ScanService · RealtimeService · ResponseService · UpdateService   │
│  LicenseService · TelemetryService                                 │
└───────────────▲───────────────────────────────────────────────────┘
                │ (usa puertos + dominio)
┌───────────────┴───────────────────────────────────────────────────┐
│  DOMINIO (reglas de negocio puras, sin I/O, 100% testeable)        │
│  Verdict · Signal · Detector(Port) · DecisionEngine · RiskScore    │
│  BehaviorGraph · Indicator(ATT&CK) · Threat · QuarantineItem       │
└───────────────────────────────────────────────────────────────────┘
```

### 4.2 Puertos (traits) clave — generalización del diseño actual

- **`Detector`** (generaliza el actual `engine.rs`): toda capa de detección
  implementa
  ```text
  trait Detector {
      fn id(&self) -> DetectorId;
      fn stage(&self) -> Stage;              // Estática | Runtime | Nube
      fn analyze(&self, ctx: &AnalysisContext) -> Vec<Signal>;
  }
  ```
  Adaptadores: `SignatureDetector`, `HeuristicDetector`, `YaraDetector`,
  `PeDetector`, `EntropyDetector`, `ReputationDetector`, `MlDetector`,
  `BehaviorDetector`, `MemoryDetector`, `NetworkDetector`, `SandboxDetector`.
  → Las 3 capas actuales se **mueven** aquí sin cambiar su lógica.
- **`EventSource`** (nuevo, tiempo real): produce `SystemEvent` (fichero,
  proceso, imagen cargada, registro, red). Adaptadores por SO:
  `InotifyFanotify` (Linux), `WinFsEtw` (Windows), `EndpointSecurity` (macOS).
- **`ResponseAction`** (nuevo): `Quarantine`, `KillProcess`, `IsolateHost`,
  `Rollback`, `Alert`. Permite respuesta graduada y testeable.
- **`ThreatIntel`** (generaliza reputación): `lookup`, `iocs`, `yara_rules`,
  `sigma_rules`, `ml_model_pull`.
- **`ModelRuntime`** (ML): `predict(features) -> score` (adaptador ONNX/GBDT).
- **`SecureChannel`**: transporte con TLS + verificación de firma (updates).

### 4.3 Estructura física propuesta (workspace, sin romper lo actual)

`endpoint/agent-core` **sigue compilando el binario `ngav`** durante la
transición. Se introduce un workspace y se extraen crates de forma **mecánica**
(mismo comportamiento, tests intactos):

```
endpoint/
  Cargo.toml                # [workspace]
  crates/
    ngav-domain/            # Verdict, Signal, Detector, DecisionEngine, RiskScore
    ngav-detect-static/     # signatures, heuristics, entropy, pe, yara
    ngav-reputation/        # (extraído) local + cloud
    ngav-behavior/          # NUEVO: modelo de eventos, indicadores, scoring
    ngav-realtime/          # NUEVO: EventSource + planificador + caché
    ngav-platform/          # adaptadores SO (win/linux/macos) tras cfg
    ngav-response/          # quarantine, kill, rollback (ResponseAction)
    ngav-cloud-client/      # TLS + firma; reputación, intel, updates
    ngav-license/           # (extraído) + token firmado
    ngav-api/               # servidor HTTP: SOLO transporte + auth
    ngav-app/               # casos de uso (ScanService, RealtimeService…)
    ngav-agent/             # binario: wiring (composition root)
  ui/                       # sin cambios
```

Beneficios: límites de compilación (tiempos), tests por crate, `cargo bench` por
crate, reemplazo de un adaptador sin recompilar el dominio, y **cumplimiento de
SRP/DIP**. La UI y los servicios Go **no se tocan** en la extracción.

---

## 5. Decisión técnica troncal: dependencias curadas y firmadas

La restricción "sólo `std`" **debe relajarse de forma deliberada y auditada**
para alcanzar nivel NGAV. Justificación por necesidad concreta:

| Necesidad | Con `std` hoy | Dependencia propuesta | Por qué |
|-----------|---------------|-----------------------|---------|
| Vigilancia FS multiplataforma | imposible eficiente | `notify` (+ raw fanotify/ETW) | evita polling; usa APIs del kernel |
| Async I/O (tiempo real, red) | hilos manuales | `tokio` | miles de eventos concurrentes con bajo coste |
| TLS | ninguno | `rustls` | canal seguro sin OpenSSL |
| Serialización | JSON a mano | `serde`/`serde_json` | correcto, seguro, mantenible |
| Firma de updates/licencia | ninguno | `ed25519-dalek` | anti-tamper, anti-MITM |
| Cifrado de cuarentena | XOR | `chacha20poly1305` | cifrado autenticado |
| YARA real | substring | `yara-x` (Rust, VirusTotal) | reglas estándar de la industria |
| Parser PE | `MZ` | `goblin`/`pelite` | imports, secciones, entropía |
| Inferencia ML | ninguno | `ort` (ONNX Runtime) o `tract` (puro Rust) | modelos reales en el endpoint |
| Multi-hilo escaneo | secuencial | `rayon` | paralelismo de datos trivialmente correcto |
| Aho-Corasick (firmas) | naïve | `aho-corasick` | miles de patrones en una pasada |
| Logging/tracing | `eprintln!` | `tracing` | observabilidad estructurada |
| Errores | `String` | `thiserror` | errores de dominio tipados |
| Benchmarks | ninguno | `criterion` | medición de regresiones |
| Fuzzing | ninguno | `cargo-fuzz` | robustez de parsers |

**Mitigación de riesgos de suministro (supply-chain):** `cargo-vet`/`cargo-deny`
para auditar y fijar dependencias; `Cargo.lock` versionado; builds
reproducibles; SBOM. Se mantiene el binario **autocontenido** (estático) y el
arranque `.exe`. La compatibilidad de comandos y de la API HTTP se preserva.

> Esta decisión se aplica **de forma incremental**: cada etapa introduce sólo
> las dependencias que necesita, con su justificación y su verificación de
> licencia. No se hace un "big bang".

---

## 6. Diseño del motor de comportamiento (marca de la casa NGAV)

El corazón de un NGAV es **decidir por lo que un programa HACE**, no por lo que
ES. Diseño (implementación en Etapa 2):

- **Modelo de eventos** normalizado y agnóstico de SO: `ProcessStart`,
  `ImageLoad`, `RemoteThread`, `HandleOpen(target)`, `RegistrySet`,
  `TaskCreate`, `WmiExec`, `ServiceInstall`, `DriverLoad`, `FileWrite`,
  `NetConnect`. Fuente: ETW en Windows (adaptador), inotify/eBPF en Linux.
- **Grafo por árbol de proceso** (`BehaviorGraph`): acumula indicadores y
  correlaciona secuencias (cadena de ataque estilo **MITRE ATT&CK**).
- **Indicadores mapeados a técnicas** con peso: DLL Injection
  (`CreateRemoteThread`+`WriteProcessMemory`+`VirtualAllocEx`), Reflective DLL,
  **Process Hollowing** (`ZwUnmapViewOfSection`+`SetThreadContext`), **APC
  Injection** (`QueueUserAPC`), **RunPE**, **robo LSASS** (`OpenProcess(lsass)`
  + `MiniDumpWriteDump`), **AMSI/Defender bypass**, **LOLBins/LotL**
  (certutil, mshta, regsvr32, rundll32), persistencia (registro Run, tareas,
  WMI, servicios, drivers), y ransomware (enumeración masiva + escritura de
  alta entropía + borrado de shadow copies + toque de *canary files*).
- **Sistema de puntuación de riesgo acumulativo** por proceso: múltiples
  indicadores débiles suman hasta cruzar umbrales → `Sospechoso`/`Malicioso`.
  **Nunca** decide una sola técnica (cumple tu requisito de multicapa).
- **Testeable hoy**: el motor consume un *stream* de eventos; se prueba con
  secuencias sintéticas (unit/regression) sin depender del SO. El **sensor**
  (ETW/eBPF) es un adaptador que se valida en su plataforma.

---

## 7. Pipeline de Machine Learning (real, no simulado)

Diseño completo (implementación en Etapa 3):

- **Dataset:** PE etiquetado. Estándar de la industria: **EMBER 2018**
  (~1,1 M muestras con *features* precalculadas) + muestras propias del campo
  (con consentimiento) y *clean set* de software prevalente.
- **Features (estilo EMBER):** histograma de bytes, histograma byte-entropía,
  cabecera PE, secciones (tamaños/entropía), imports/exports, strings,
  metadatos. Extractor en Rust (`goblin`) **compartido** entre entrenamiento e
  inferencia (misma featurización → sin *train/serve skew*).
- **Selección de modelo (comparativa):**

  | Modelo | Precisión (PE tabular) | Tamaño/latencia | Explicabilidad | Veredicto |
  |--------|------------------------|-----------------|----------------|-----------|
  | **LightGBM** | **alta** | **pequeño / µs** | SHAP | **Elegido (endpoint)** |
  | XGBoost | alta | medio | SHAP | alternativa |
  | Random Forest | media-alta | grande | media | descartado (tamaño) |
  | Redes densas | media | medio | baja | no supera a GBDT en tabular |
  | Isolation Forest | — | pequeño | baja | **anomalía** (no supervisado) |
  | Autoencoder | — | medio | baja | anomalía (nube) |
  | Transformer ligero | alta (secuencias) | grande | baja | **comportamiento/scripts (nube)** |

  **Conclusión:** GBDT (**LightGBM**) para clasificación estática de PE en el
  endpoint (mejor relación precisión/tamaño/latencia y explicable con SHAP);
  Isolation Forest para anomalía local; Transformer ligero reservado a análisis
  de secuencias/scripts en la nube.
- **MLOps:** recolección → limpieza → *feature store* → entrenamiento →
  validación con *gates* (FP sobre clean set, recall sobre regresión, robustez
  adversarial) → **registro y versionado** → firma → despliegue **canario** →
  inferencia ONNX en el endpoint. Defensa anti-envenenamiento ya diseñada en
  `docs/aprendizaje-continuo.md`.
- **Inferencia en Rust:** `ort` (ONNX Runtime) o `tract` (puro Rust, sin runtime
  externo) tras el puerto `ModelRuntime`. El `MlDetector` emite `Signal` con
  `Source::MachineLearning` y **explicación** (top features SHAP) para el
  informe al usuario.

---

## 8. Otras capas (diseño resumido; etapas posteriores)

- **IA explicable:** genera un informe legible ("por qué es peligroso": técnicas
  ATT&CK detectadas, features del modelo, comportamiento observado). Analiza
  scripts (PowerShell/JS/VBS), macros Office y PDFs con desofuscación + reglas.
- **Sandbox:** ejecución aislada (microVM/contenedor) con instrumentación de FS,
  registro, procesos, hilos, memoria, red, handles, pipes → informe + puntaje.
  Local ligero (opcional) y **remoto** en la nube (recomendado por coste).
- **Memory Scanner:** shellcode, inyección, *manual mapping*, páginas **RWX**,
  hooks, heap spray, ROP, código sin respaldo en disco. Requiere WinAPI
  (`VirtualQueryEx`, `NtQueryVirtualMemory`) → adaptador Windows.
- **Motor de red:** DNS/HTTP/TLS/SNI/**JA3**, reputación IP, geolocalización,
  Tor/VPN/botnet/**C2**, **DGA**, **Fast Flux**, exfiltración. Puerto
  `NetworkSensor` + detección en dominio.
- **Protección web:** bloqueo de phishing/descargas maliciosas vía listas + ML +
  reputación (extensión de navegador o proxy local).
- **Autoprotección:** PPL/ELAM (Windows), watchdog mutuo, protección de
  ficheros/registro/servicio, verificación de integridad, y **auth del canal
  local** (arreglo del riesgo §3.2).
- **Arquitectura lista para drivers:** puertos `EventSource`/`FsFilter` de modo
  que un **minifilter/driver** WHQL se enchufe cuando exista, sin cambiar el
  dominio. Hoy: adaptadores en modo usuario (ETW/inotify).
- **Nube ampliada:** intel global, reputación distribuida (KV), IOC, **YARA**,
  **Sigma**, ML en nube y **sandbox remoto**; datos en cola (Kafka) + almacén
  analítico. Telemetría **anonimizada y opcional**: sólo hashes, IOC, metadatos
  y estadísticas — **nunca ficheros privados**.

---

## 9. Objetivos de rendimiento (SLO, medidos con `criterion` y en runtime)

| Métrica | Objetivo | Cómo se logra |
|---------|----------|---------------|
| CPU en reposo | < 2 % | tiempo real basado en eventos (no polling), triage barato primero |
| RAM (agente+UI) | < 200 MB | `mmap`, streaming, UI Tauri/WebView, modelos cuantizados |
| Arranque | < 3 s | carga perezosa de modelos, índices mmap |
| Escaneo | incremental + `rayon` | caché de veredicto por hash, pool multinúcleo |
| Hash/entropía | SIMD cuando aporte | `std::simd`/intrínsecos con *fallback* |

---

## 10. Estrategia de pruebas (nivel empresarial)

- **Unitarias** (por crate, dominio 100%). **Integración** (pipeline completo por
  ficheros de muestra). **Regresión** (corpus EICAR + limpios prevalentes +
  casos históricos; gate de FP). **Rendimiento** (`criterion`, umbrales de SLO
  en CI). **Seguridad** (auth del API, límites de tamaño, TLS/firma).
  **Fuzzing** (`cargo-fuzz` sobre parsers PE/JSON/protocolo). **Benchmarks** de
  detección (recall/FP) por versión. CI con **matriz Linux + Windows**.

---

## 11. Plan por etapas (Definition of Done por etapa)

Cada etapa termina sólo cuando: código + tests (todas las categorías aplicables)
+ benchmarks/SLO + regresiones corregidas + **documentación del módulo**
(arquitectura, diagrama, flujo, dependencias, límites, riesgos, decisiones) +
commit. **No se avanza sin cerrar la anterior.**

| Etapa | Contenido | Testable en este entorno |
|-------|-----------|---------------------------|
| **0** | **Análisis + arquitectura (este documento)** | ✅ (hecho) |
| **1** | **Fundaciones + Protección en tiempo real.** Workspace y extracción mecánica a crates (sin cambiar lógica; tests intactos); unificar `scanner`/`scanjob` (elimina duplicación, recupera incremental en GUI); puerto `Detector` (mover las 3 capas); **auth del API local** (token + verificación Origin/Host, tope de body) — arregla §3.2; puerto `EventSource` + **adaptador Linux (inotify/fanotify) real y testeado** + adaptador Windows (compilado, validado en CI Windows); `RealtimeService` con debounce, exclusiones, caché por hash y pool `rayon`. | ✅ núcleo + Linux; ⚠️ Windows en CI |
| **2** | **Motor de comportamiento** (grafo por proceso, indicadores ATT&CK, scoring de riesgo) + sensor de procesos. | ✅ scoring; ⚠️ ETW en Windows |
| **3** | **Pipeline ML real** (dataset→train→validación→ONNX→`MlDetector`) + explicabilidad. | ✅ pipeline; ⚠️ dataset según acceso de red |
| **4** | **PE parser + YARA-X + entropía por sección** (reemplazan sin borrar la heurística actual). | ✅ |
| **5** | **Memory Scanner** (Windows) + **motor de red** (DNS/TLS/JA3/C2/DGA). | ⚠️ Windows/red |
| **6** | **Sandbox remoto** + nube ampliada (intel, YARA/Sigma, ML nube) + **telemetría anonimizada opcional**. | parcial |
| **7** | **Autoprotección** (PPL/ELAM, watchdog, integridad) + **licencia firmada** + cuarentena cifrada + **TLS/firma de updates (TUF)**. | ⚠️ Windows |
| **8** | **UI modernizada** (timeline de amenazas, visor de eventos, modo básico/experto, estadísticas). | ✅ |
| **9** | **Arquitectura de drivers** (minifilter/registro/procesos) — cuando haya firma WHQL. | ❌ requiere Windows+cert |

---

## 12. Limitaciones honestas y prerrequisitos

- **Entorno de build actual = Linux (contenedor).** Se puede construir y **probar
  de verdad**: dominio, motor de comportamiento (con eventos), tiempo real en
  **Linux (inotify)**, PE parser, YARA-X, pipeline ML e inferencia ONNX,
  API+auth, cifrado, firma. **No se puede ejecutar/validar aquí**: ETW,
  ReadDirectoryChangesW, memory scanner Windows, PPL/ELAM y drivers → requieren
  **una máquina/CI Windows**. La arquitectura los deja enchufables y se validan
  en CI Windows.
- **Prerrequisitos externos** (los aportás vos): dataset PE (o acceso de red para
  EMBER), **certificado de firma de código** (para `.exe` sin aviso y para
  drivers WHQL), cuenta de **Stripe** real, e infraestructura de nube si se
  despliega a escala. Sin ellos se entrega el código y la validación local; la
  parte que depende del recurso externo queda lista para conectar.
- **Sin exageraciones:** no se venderá como "equivalente a CrowdStrike" hasta que
  las capas estén implementadas y **medidas** (recall/FP) contra un corpus real.

---

## 13. Recomendación

Aprobar el arranque de la **Etapa 1 (Fundaciones + Protección en tiempo real)**,
que además **corrige el riesgo de seguridad más grave hoy** (API local sin
autenticación) y **elimina la duplicación** `scanner`/`scanjob`, dejando la base
limpia (workspace + puertos) sobre la que se montan las etapas 2–9. Compatibilidad
total: comandos CLI, API HTTP y UI siguen funcionando igual.
