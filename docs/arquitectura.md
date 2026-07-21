# Arquitectura del Sistema — NGAV

**Equipo redactor (roles):** Arquitecto de Software · Experto en Ciberseguridad · Ingeniero de IA ·
Desarrollador de Sistemas · Ingeniero DevOps.

Este documento describe la arquitectura global, los componentes, las tecnologías, el backend en la
nube, las APIs, la comunicación entre módulos, actualizaciones, licenciamiento y la estrategia de
escalabilidad para millones de usuarios.

---

## 1. Visión general de la arquitectura

El sistema sigue un modelo **cliente-nube híbrido** con tres planos:

1. **Endpoint (cliente)** — Agente ligero que ejecuta la mayor parte de la detección **localmente**
   (funciona offline). Compuesto por un servicio/daemon con privilegios, drivers de kernel, un motor
   de detección y una UI sin privilegios.
2. **Plano de nube (backend)** — Servicios de threat intelligence, telemetría, sandbox a escala,
   entrenamiento de modelos (MLOps), distribución de actualizaciones, licenciamiento y APIs.
3. **Plano de gestión** — Panel de administración web (consola) para empresas y para el equipo
   interno de operaciones/analistas (SOC).

> **Decisión de arquitectura clave:** la detección crítica ocurre **en el endpoint** para garantizar
> latencia baja, protección offline y privacidad. La nube aporta *inteligencia colectiva*, análisis
> pesado (sandbox) y entrenamiento, pero **nunca es un punto único de fallo** para la protección.

### 1.1 Diagrama de alto nivel

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                   ENDPOINT                                     │
│                                                                                │
│  ┌────────────┐   IPC seguro   ┌───────────────────────────────────────────┐  │
│  │   UI (GUI) │◄──────────────►│        Servicio/Daemon (privilegiado)      │  │
│  │  sin priv. │   gRPC/UDS     │                                            │  │
│  └────────────┘                │  ┌──────────────────────────────────────┐  │  │
│                                │  │        MOTOR DE DETECCIÓN HÍBRIDO      │  │  │
│  ┌────────────┐                │  │  Firmas · Heurística · Comportamiento │  │  │
│  │ Kernel     │  eventos       │  │  ML local · Anomalías · Reputación    │  │  │
│  │ Drivers    │───────────────►│  │            Motor de decisión          │  │  │
│  │ (minifilter│                │  └──────────────────────────────────────┘  │  │
│  │  / eBPF)   │                │  ┌───────────┐ ┌───────────┐ ┌──────────┐  │  │
│  └────────────┘                │  │ Cuarentena│ │Self-defense│ │Update mgr│  │  │
│                                │  └───────────┘ └───────────┘ └──────────┘  │  │
│                                └───────────────────┬───────────────────────┘  │
└────────────────────────────────────────────────────┼──────────────────────────┘
                                                     │ mTLS (HTTPS/gRPC)
                                                     ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              PLANO DE NUBE (Backend)                            │
│                                                                                │
│  ┌────────────┐  ┌───────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ API Gateway│  │ Telemetría /  │  │ Reputación   │  │ Threat Intel /     │   │
│  │  (mTLS)    │  │ Ingesta (Kafka│  │ (file/URL/IP)│  │ Feeds (STIX/TAXII) │   │
│  └─────┬──────┘  │  streaming)   │  └──────────────┘  └────────────────────┘   │
│        │         └───────┬───────┘                                             │
│  ┌─────▼──────┐  ┌────────▼────────┐ ┌──────────────┐  ┌────────────────────┐  │
│  │ Licencias  │  │ Sandbox cluster │ │ Data Lake    │  │ MLOps / Entrenamiento│ │
│  │ (billing)  │  │ (detonación)    │ │ (S3/Delta)   │  │ + Model Registry    │  │
│  └────────────┘  └─────────────────┘ └──────────────┘  └────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │ Distribución de actualizaciones (CDN, paquetes firmados)                │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
        ▲
        │ HTTPS
┌───────┴────────────────────────────┐
│  Panel de administración (Web SPA)  │  ← Empresas (multi-tenant) + SOC interno
└─────────────────────────────────────┘
```

---

## 2. Diagrama de componentes (detallado)

### 2.1 Componentes del endpoint

| Componente | Responsabilidad | Privilegios |
|------------|-----------------|-------------|
| **Kernel drivers** | Interceptar E/S de ficheros (minifilter en Windows / Fanotify/eBPF en Linux / EndpointSecurity en macOS), procesos, red, registro | Kernel |
| **Servicio/Daemon** | Orquestación, motor de detección, cola de escaneo, cuarentena, comunicación con la nube | Sistema (SYSTEM/root) |
| **Motor de detección** | Ejecuta las 8 técnicas y consolida veredicto | Sistema |
| **Módulo de self-defense** | Protege procesos, ficheros, claves de registro y servicios del propio AV | Sistema/Kernel |
| **Update manager** | Descarga y verifica firmas y modelos firmados; aplica deltas | Sistema |
| **Gestor de licencias** | Valida y cachea el estado de la licencia | Sistema |
| **UI / Tray** | Interfaz de usuario, notificaciones | Usuario (sin privilegios) |
| **Bus IPC** | Canal seguro UI ↔ servicio (gRPC sobre named pipe / Unix Domain Socket) | — |

### 2.2 Componentes de nube (microservicios)

- **API Gateway** — Terminación mTLS, autenticación, rate limiting, enrutamiento.
- **Servicio de telemetría/ingesta** — Recibe eventos y metadatos (no ficheros por defecto); los
  publica en un stream (Kafka).
- **Servicio de reputación** — Consulta rápida (key-value) de hashes de ficheros, URLs, IPs y
  certificados con puntuación de reputación.
- **Servicio de sandbox** — Detona muestras sospechosas en VMs/microVMs aisladas y produce informes
  de comportamiento.
- **Servicio de threat intelligence** — Ingiere feeds externos (STIX/TAXII, comerciales, OSINT),
  normaliza IoCs y genera firmas/reglas.
- **Plataforma MLOps** — Feature store, entrenamiento, validación, registro de modelos, despliegue
  canario.
- **Servicio de actualizaciones** — Empaqueta, firma y publica firmas y modelos vía CDN.
- **Servicio de licencias/billing** — Ciclo de vida de licencias, planes, activaciones, facturación.
- **Servicio de gestión (multi-tenant)** — Backend del panel de administración empresarial.
- **Data Lake / Warehouse** — Almacenamiento analítico de telemetría para entrenamiento y BI.

---

## 3. Tecnologías recomendadas

### 3.1 Endpoint

| Área | Tecnología recomendada | Alternativas | Justificación |
|------|------------------------|--------------|---------------|
| Drivers de kernel Windows | C/C++ (WDK, Minifilter, WFP, ELAM) | — | Requisito de la plataforma |
| Linux | eBPF (CO-RE, libbpf) + Fanotify | LSM, kernel module | eBPF es seguro, sin recompilar kernel |
| macOS | EndpointSecurity + Network Extension (Swift/C++) | — | APIs oficiales de Apple |
| Motor/servicio | **Rust** (núcleo) + C/C++ (interop) | Go, C++ | Rust: seguridad de memoria + rendimiento nativo, crítico en software de seguridad |
| ML en el endpoint | ONNX Runtime, TensorFlow Lite | LightGBM nativo | Inferencia portable y ligera |
| UI de escritorio | **Tauri** (Rust + WebView) | Qt (C++), Electron, WinUI3/SwiftUI nativas | Tauri: binario pequeño, bajo consumo de RAM vs Electron |
| Serialización/IPC | gRPC + Protobuf | FlatBuffers, Cap'n Proto | Contratos tipados, multiplataforma |

> **Justificación de Rust como lenguaje del núcleo:** en un producto de seguridad, las
> vulnerabilidades de memoria (buffer overflows, use-after-free) del propio agente serían
> catastróficas (superficie de ataque con privilegios de SYSTEM). Rust elimina clases enteras de
> estos fallos manteniendo rendimiento C-like. C/C++ se limita a los drivers de kernel donde es
> obligatorio.

### 3.2 Backend / nube

| Área | Tecnología | Justificación |
|------|------------|---------------|
| Microservicios | **Go** (servicios de I/O y red) + **Python** (ML/data) + **Rust** (componentes de rendimiento crítico) | Go: concurrencia y throughput; Python: ecosistema ML; Rust: hot paths |
| Streaming/ingesta | Apache Kafka (o Redpanda) | Alto throughput, durabilidad, replay |
| Orquestación | Kubernetes (EKS/GKE/AKS) | Estándar de escalado |
| Sandbox | Firecracker microVMs, CAPEv2/Cuckoo3, QEMU/KVM | Aislamiento fuerte con arranque rápido |
| ML/MLOps | PyTorch, XGBoost/LightGBM, Kubeflow/MLflow, Feast (feature store) | Ecosistema maduro |
| CDN | CloudFront / Cloudflare / Akamai | Distribución global de actualizaciones |
| IaC | Terraform + Helm | Reproducibilidad |
| Observabilidad | Prometheus, Grafana, OpenTelemetry, Loki, Jaeger | Métricas/trazas/logs |

### 3.3 Bases de datos

| Uso | Tecnología | Motivo |
|-----|------------|--------|
| Reputación (hashes/URL/IP) | **Redis / ScyllaDB (o DynamoDB)** | Lecturas de baja latencia a escala masiva |
| Metadatos, licencias, tenants, usuarios | **PostgreSQL** (con particionado / Citus) | Transaccional, relacional, ACID |
| Telemetría cruda / eventos | **ClickHouse** (o Druid) | Analítica OLAP sobre miles de millones de eventos |
| Data Lake (muestras/features) | **S3 + Delta Lake / Iceberg** | Almacenamiento barato y versionado para ML |
| Búsqueda/IOC hunting | **OpenSearch/Elasticsearch** | Búsqueda full-text y correlación |
| Grafo de amenazas (relaciones IoC) | **Neo4j / JanusGraph** | Correlación de campañas y actores |
| Cola/streaming | **Kafka** | Desacople de ingesta |
| Cache de firmas/config | **Redis** | Baja latencia |

**Base de datos local del endpoint:** **SQLite** (cifrado con SQLCipher) para configuración,
historial, cuarentena e índice de escaneo incremental; y un almacén compacto en memoria/mmap para las
bases de firmas (bloom filters + tablas hash).

---

## 4. Lenguajes de programación (resumen y justificación)

| Capa | Lenguaje | Por qué |
|------|----------|---------|
| Drivers de kernel | C / C++ | Único soportado por los frameworks de kernel |
| Núcleo del agente | **Rust** | Seguridad de memoria + rendimiento; reduce la superficie de ataque del propio AV |
| UI de escritorio | Rust + TypeScript (Tauri/WebView) | Reutiliza el núcleo Rust, UI moderna con web tech |
| Servicios de red/ingesta | Go | Concurrencia masiva, latencia baja |
| ML / data engineering | Python | Ecosistema (PyTorch, pandas, scikit-learn) |
| Hot paths backend (reputación, parsing) | Rust | Rendimiento por petición |
| Panel de administración (frontend) | TypeScript + React | Ecosistema SPA maduro |
| IaC / automatización | HCL (Terraform), YAML (Helm), Bash/Python | DevOps estándar |

---

## 5. Estructura de carpetas

Ver documento dedicado: [`estructura-carpetas.md`](estructura-carpetas.md). Resumen:

```
ngav/
├── endpoint/           # Agente (Rust) + drivers (C/C++) + UI (Tauri)
├── cloud/              # Microservicios backend (Go/Python/Rust)
├── ml/                 # Pipelines de entrenamiento, modelos, evaluación
├── admin-console/      # Panel de administración (React)
├── shared/             # Contratos protobuf, esquemas, librerías comunes
├── infra/              # Terraform, Helm, CI/CD
└── docs/               # Documentación técnica
```

---

## 6. APIs

Todas las APIs públicas usan **mTLS** (el cliente presenta un certificado por dispositivo emitido en
la activación) y versionado (`/v1/`). Formato: gRPC/Protobuf para cliente↔nube (eficiente, binario) y
REST/JSON para el panel de administración.

### 6.1 API cliente ↔ nube (gRPC)

| Método | Descripción |
|--------|-------------|
| `Reputation.Lookup(hashes[], urls[], ips[])` | Consulta reputación en lote |
| `Telemetry.Submit(events[])` | Envío de telemetría anonimizada (batched, comprimido) |
| `Sample.Upload(metadata, chunk)` | Subida **opcional y con consentimiento** de una muestra sospechosa |
| `Sandbox.GetVerdict(sampleId)` | Consulta el veredicto de detonación |
| `Updates.CheckManifest(currentVersions)` | Devuelve deltas de firmas/modelos a aplicar |
| `Updates.FetchPackage(packageId)` | Descarga de paquete firmado (o redirección a CDN) |
| `License.Validate(deviceId, token)` | Validación/renovación de licencia |
| `Enroll.Activate(licenseKey, deviceInfo)` | Alta del dispositivo y emisión de certificado cliente |

### 6.2 API de administración (REST)

| Recurso | Métodos | Uso |
|---------|---------|-----|
| `/v1/tenants` | CRUD | Gestión de organizaciones |
| `/v1/devices` | GET/PATCH | Inventario, estado, aislamiento remoto |
| `/v1/policies` | CRUD | Políticas de escaneo/protección por grupo |
| `/v1/incidents` | GET/PATCH | Alertas, triage, respuesta |
| `/v1/quarantine` | GET/POST | Ver, restaurar o eliminar en remoto |
| `/v1/reports` | GET | Cumplimiento, KPIs de seguridad |
| `/v1/licenses` | CRUD | Asignación de asientos |

### 6.3 API interna (SOC/analistas)

Endpoints para: gestión de muestras, etiquetado, promoción de modelos, gestión de feeds de threat
intel, y creación/publicación de firmas.

---

## 7. Comunicación entre módulos

### 7.1 En el endpoint

- **Kernel ↔ Servicio:** cola de eventos por *shared memory ring buffer* / puerto de comunicación de
  filtro (FilterCommunicationPort en Windows, mapas eBPF/perf buffer en Linux). Prioriza baja latencia
  y contrapresión (drop controlado bajo carga).
- **UI ↔ Servicio:** **gRPC sobre named pipe (Windows) / Unix Domain Socket (Unix)** con
  autenticación (verificación de firma del binario UI + ACLs del socket). La UI **nunca** tiene
  privilegios; solo solicita acciones que el servicio autoriza.
- **Motor de decisión:** las capas de detección publican veredictos parciales a un *scoring bus*
  interno que consolida (ver `motor-deteccion.md`).

### 7.2 Endpoint ↔ Nube

- Canal **mTLS** persistente (gRPC) con reconexión y *backoff*.
- Telemetría en lotes, comprimida (zstd), con presupuesto de ancho de banda configurable.
- **Modo degradado:** si la nube no está disponible, el endpoint sigue protegiendo con su caché local
  de reputación, firmas y modelos; encola telemetría para reenvío.

### 7.3 Entre microservicios (nube)

- **Asíncrono** por defecto vía Kafka (ingesta, sandbox, entrenamiento) para desacoplar y absorber
  picos.
- **Síncrono** vía gRPC interno para consultas de baja latencia (reputación).
- **Service mesh** (Istio/Linkerd) para mTLS interno, retries y observabilidad.

---

## 8. Sistema de actualizaciones

Se distinguen **cuatro tipos** de actualización con cadencias distintas:

| Tipo | Contenido | Cadencia | Mecanismo |
|------|-----------|----------|-----------|
| Firmas / IoCs | Hashes, reglas YARA, patrones | Cada 15–60 min (o push) | Deltas binarios pequeños vía CDN |
| Modelos ML | Modelos ONNX firmados | Diaria/semanal (canario) | Paquete firmado, rollback disponible |
| Reglas de comportamiento | Reglas de detección (DSL) | Diaria o push urgente | Paquete firmado |
| Motor / cliente | Binarios del agente | Mensual/trimestral | Actualizador con verificación e instalación segura |

**Seguridad de las actualizaciones (crítico):**

1. **Firma de código y de contenido:** cada paquete se firma (Ed25519/ECDSA). El endpoint verifica la
   firma **antes** de aplicar. Se usa una **cadena de confianza** con claves rotables y *pinning*.
2. **Protección anti-rollback:** versionado monotónico firmado (evita que un atacante fuerce una base
   antigua vulnerable).
3. **Transparencia/reproducibilidad:** logs tipo *transparency log* de artefactos publicados
   (inspirado en Sigstore/TUF). **Se recomienda adoptar el framework TUF** (The Update Framework) para
   resistir compromisos de la infraestructura de distribución.
4. **Despliegue canario:** modelos y reglas se despliegan primero a un % de la flota; métricas de FP/FN
   y estabilidad se vigilan antes del despliegue global. **Rollback automático** si se degradan.
5. **Deltas:** solo se transmiten diferencias para minimizar ancho de banda.

---

## 9. Sistema de licencias

**Modelo:** licenciamiento por suscripción (SaaS) con asientos por dispositivo, planes (Home, Pro,
Business, Enterprise) y activación online con *grace period* offline.

**Diseño técnico:**

- **Activación:** el cliente canjea una *license key* → el backend valida el plan, registra el
  dispositivo y **emite un certificado cliente** (usado luego para mTLS) + un *entitlement token*
  firmado (JWT/PASETO) con las capacidades habilitadas y su expiración.
- **Validación offline:** el token firmado se valida localmente con la clave pública embebida; permite
  operar sin conexión durante un periodo de gracia (p. ej. 14–30 días) antes de requerir revalidación.
- **Anti-abuso:** binding a huella de dispositivo (no invasiva), límite de activaciones concurrentes,
  detección de compartición, y revocación remota (CRL/estado en el token corto).
- **Enterprise:** licenciamiento por volumen, integración con el panel (asientos, grupos), soporte de
  *air-gapped* mediante servidor de licencias on-premise.
- **Facturación:** integración con proveedor de pagos (Stripe/Chargebee); eventos de ciclo de vida
  (trial, activo, suspendido, cancelado) gestionados por el servicio de billing.

> **Alternativa considerada:** licencias puramente offline (clave que se valida solo localmente). Se
> descarta como modelo único porque impide revocación y control de asientos; se mantiene como *fallback*
> temporal mediante el token firmado de corta duración.

---

## 10. Panel de administración

Ver detalle en [`interfaz.md`](interfaz.md). Características principales:

- **Multi-tenant** con RBAC (roles: admin de org, analista, solo lectura).
- Dashboard de postura de seguridad, inventario de dispositivos, estado de protección en tiempo real.
- Gestión de **políticas** por grupos (calendarios de escaneo, exclusiones, nivel de heurística).
- **Consola de incidentes**: alertas, triage, línea de tiempo de eventos (capacidades EDR),
  aislamiento de host remoto, *kill process*, restaurar/eliminar cuarentena.
- Informes de cumplimiento (ISO 27001, SOC 2, GDPR) y exportación.
- Integraciones: SIEM (syslog/CEF), SSO (SAML/OIDC), API y webhooks.

---

## 11. Cliente de escritorio

Ver detalle en [`interfaz.md`](interfaz.md) y [`rendimiento.md`](rendimiento.md). Resumen:

- **Tauri** (núcleo Rust + UI web) para binario pequeño y bajo consumo.
- Multiplataforma: Windows (prioridad 1), macOS y Linux.
- Comunicación con el servicio vía IPC seguro; la UI no tiene privilegios.
- Funciones: estado de protección, escaneo rápido/completo, cuarentena, historial, actualizaciones,
  configuración avanzada, estadísticas y modo oscuro.

---

## 12. Backend en la nube

Arquitectura de **microservicios sobre Kubernetes**, *cloud-agnostic* (Terraform + Helm) con
capacidad multi-región. Patrones clave:

- **CQRS + event sourcing** en ingesta de telemetría (escritura desacoplada por Kafka, lectura sobre
  ClickHouse).
- **Idempotencia** en endpoints de ingesta (deduplicación por id de evento).
- **Multi-tenancy** con aislamiento lógico (row-level security en Postgres) y físico opcional para
  Enterprise.
- **Secretos** en Vault/KMS; cifrado en tránsito (mTLS) y en reposo (KMS).
- **DR/HA:** despliegue multi-AZ, réplicas, backups y *runbooks* de recuperación.

---

## 13. Escalabilidad para millones de usuarios

**Objetivo:** soportar decenas de millones de endpoints, cada uno generando consultas de reputación y
telemetría.

Estrategias:

1. **Empujar cómputo al endpoint.** El 95%+ de decisiones se resuelven localmente → la nube no escala
   con cada fichero, solo con lo *desconocido/sospechoso*.
2. **Reputación como servicio de lectura masiva.** Almacén key-value distribuido (ScyllaDB/Dynamo) +
   caché en el edge (CDN) para hashes muy consultados. Objetivo: p99 < 20 ms.
3. **Caché local Bloom filter.** El cliente lleva un Bloom filter de allowlist/denylist para evitar
   consultas de red innecesarias (solo consulta ante incertidumbre).
4. **Ingesta desacoplada y con muestreo.** Telemetría por lotes, comprimida, con *sampling* adaptativo
   y presupuestos por dispositivo. Kafka absorbe picos; el procesamiento escala horizontalmente.
5. **Autoescalado.** HPA por métricas (CPU + latencia + lag de consumidor Kafka); *cluster autoscaler*.
6. **Multi-región + CDN.** Actualizaciones y reputación servidas desde el edge; enrutamiento por
   geolocalización.
7. **Aislamiento del sandbox.** El cluster de detonación escala de forma independiente y con colas de
   prioridad (no bloquea la ruta de detección).
8. **Degradación elegante.** Bajo sobrecarga, se priorizan reputación y actualizaciones críticas sobre
   telemetría analítica.

**Estimación de capacidad (orden de magnitud):** con 10 M de endpoints y una media de 1 consulta de
reputación *cache-miss* cada pocos minutos por dispositivo activo, el diseño apunta a decenas de miles
de QPS en reputación — perfectamente asumible por un almacén distribuido con caché de edge; la mayoría
de consultas se resuelven en CDN/edge sin tocar el origen.

---

## 14. Resumen de decisiones y alternativas

| Decisión | Elegido | Alternativa | Motivo |
|----------|---------|-------------|--------|
| Lenguaje del núcleo | Rust | C++ / Go | Seguridad de memoria en software privilegiado |
| UI | Tauri | Electron / Qt | Menor RAM y binario; reutiliza Rust |
| Detección | Híbrida local-first | Solo nube | Protección offline, privacidad, latencia |
| Aprendizaje | En nube + validación | Entrenamiento en endpoint | Evita data poisoning en el dispositivo |
| Actualizaciones | TUF + firma + canario | Firma simple | Resistencia a compromiso de infraestructura |
| Sandbox | Firecracker microVM | Contenedores | Aislamiento más fuerte |
| Reputación | KV distribuido + edge | RDBMS | Latencia y escala |

Continúa en: [`motor-deteccion.md`](motor-deteccion.md) · [`aprendizaje-continuo.md`](aprendizaje-continuo.md) ·
[`rendimiento.md`](rendimiento.md) · [`seguridad-producto.md`](seguridad-producto.md) ·
[`interfaz.md`](interfaz.md) · [`roadmap.md`](roadmap.md).
