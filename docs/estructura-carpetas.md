# Estructura de Carpetas (Monorepo)

Se propone un **monorepo** para compartir contratos (protobuf), facilitar cambios atómicos entre
cliente y servidor, y unificar CI/CD. Alternativa: multi-repo por dominio (endpoint / cloud / ml /
console) si los equipos crecen mucho y necesitan cadencias independientes.

```
ngav/
├── README.md
├── docs/                          # Documentación técnica (este diseño)
│
├── endpoint/                      # AGENTE DE ESCRITORIO
│   ├── agent-core/                # Núcleo del servicio/daemon (Rust)
│   │   ├── src/
│   │   │   ├── engine/            # Motor de detección (orquestador)
│   │   │   │   ├── signatures/    # Firmas, YARA, fuzzy hashing
│   │   │   │   ├── heuristics/    # Reglas heurísticas
│   │   │   │   ├── behavior/      # Detección por comportamiento (runtime)
│   │   │   │   ├── ml/            # Inferencia ONNX/TFLite
│   │   │   │   ├── anomaly/       # Detección de anomalías local
│   │   │   │   ├── reputation/    # Cliente de reputación + caché local
│   │   │   │   └── decision/      # Motor de decisión (scoring/fusión)
│   │   │   ├── quarantine/        # Cuarentena cifrada
│   │   │   ├── selfdefense/       # Anti-tamper (userland)
│   │   │   ├── updater/           # Update manager (TUF, verificación)
│   │   │   ├── licensing/         # Validación de licencia/entitlements
│   │   │   ├── scanner/           # Escaneo incremental, colas, scheduler
│   │   │   ├── telemetry/         # Ingesta y envío (batching, consentimiento)
│   │   │   ├── ipc/               # gRPC sobre UDS/named pipe (hacia UI)
│   │   │   └── cloud/             # Cliente mTLS hacia backend
│   │   └── Cargo.toml
│   │
│   ├── drivers/                   # Componentes de kernel (C/C++)
│   │   ├── windows/               # Minifilter, WFP, ObCallbacks, ELAM, PPL
│   │   ├── linux/                 # eBPF (CO-RE) + fanotify
│   │   └── macos/                 # EndpointSecurity + Network Extension (Swift/C++)
│   │
│   ├── ui/                        # UI de escritorio (Tauri: Rust + TS/React)
│   │   ├── src/                   # Frontend (TypeScript)
│   │   └── src-tauri/             # Puente Tauri (Rust)
│   │
│   └── installer/                 # Empaquetado e instaladores (MSI/DMG/DEB/RPM)
│
├── cloud/                         # BACKEND (microservicios)
│   ├── gateway/                   # API Gateway (mTLS, authn/z) [Go]
│   ├── reputation/                # Servicio de reputación [Rust/Go]
│   ├── telemetry-ingest/          # Ingesta → Kafka [Go]
│   ├── sandbox/                   # Orquestación de detonación [Go/Python]
│   ├── threat-intel/              # Feeds STIX/TAXII, normalización IoC [Python/Go]
│   ├── licensing/                 # Licencias y billing [Go]
│   ├── management/                # Backend multi-tenant del panel [Go]
│   ├── updates/                   # Empaquetado/firma/publicación (TUF) [Go]
│   └── common/                    # Librerías compartidas backend
│
├── ml/                            # PLATAFORMA DE ML / MLOps
│   ├── pipelines/                 # Entrenamiento, validación, promoción
│   ├── features/                  # Feature engineering + feature store (Feast)
│   ├── models/                    # Definiciones de modelos (PyTorch/LightGBM)
│   ├── evaluation/                # Gates: FP/FN, adversarial, regresión
│   ├── registry/                  # Integración Model Registry (MLflow)
│   └── export/                    # Conversión a ONNX firmado para endpoint
│
├── admin-console/                 # PANEL DE ADMINISTRACIÓN (React + TS)
│   ├── src/
│   └── public/
│
├── shared/                        # CONTRATOS Y LIBRERÍAS COMUNES
│   ├── proto/                     # Definiciones Protobuf/gRPC (fuente de verdad)
│   ├── schemas/                   # Esquemas de eventos/telemetría (Avro/JSON Schema)
│   └── crypto/                    # Utilidades de firma/verificación compartidas
│
├── infra/                         # INFRAESTRUCTURA Y DEVOPS
│   ├── terraform/                 # IaC (VPC, EKS/GKE, DBs, CDN, KMS)
│   ├── helm/                      # Charts de los microservicios
│   ├── ci/                        # Pipelines CI/CD (build, test, firma, release)
│   └── observability/             # Dashboards, alertas (Prometheus/Grafana)
│
└── tests/                         # Pruebas E2E, de rendimiento y de seguridad
    ├── e2e/
    ├── performance/               # Benchmarks de CPU/RAM/latencia (SLOs)
    └── security/                  # Fuzzing, corpus de malware (aislado), red-team
```

## Notas

- **`shared/proto` es la fuente de verdad** de los contratos: cliente y servidor generan código desde
  ahí, evitando *drift* de API.
- El **corpus de malware para pruebas** vive en infraestructura aislada y controlada (nunca en el repo
  público), con acceso restringido y trazado.
- Cada componente incluye sus propios tests unitarios junto al código.
