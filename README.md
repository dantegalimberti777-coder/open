# NGAV — Antivirus de Nueva Generación con Aprendizaje Continuo

> Documento técnico de arquitectura para un producto **Next-Generation Antivirus (NGAV / EDR)** de nivel empresarial, con motor de detección híbrido y un pipeline de aprendizaje continuo seguro.

Este repositorio contiene el **diseño técnico completo**. El documento principal está en
[`docs/arquitectura.md`](docs/arquitectura.md), complementado por documentos de detalle en `docs/`.

## Índice de la documentación

| Documento | Contenido |
|-----------|-----------|
| [`docs/arquitectura.md`](docs/arquitectura.md) | Arquitectura completa, componentes, tecnologías, backend, escalabilidad |
| [`docs/motor-deteccion.md`](docs/motor-deteccion.md) | Motor híbrido: firmas, comportamiento, heurística, ML/IA, anomalías, reputación, sandbox |
| [`docs/aprendizaje-continuo.md`](docs/aprendizaje-continuo.md) | Pipeline MLOps, threat intelligence, defensa contra data poisoning y adversarial ML |
| [`docs/rendimiento.md`](docs/rendimiento.md) | Optimización de CPU, RAM, batería, escaneo incremental |
| [`docs/interfaz.md`](docs/interfaz.md) | Diseño del cliente de escritorio y panel de administración |
| [`docs/seguridad-producto.md`](docs/seguridad-producto.md) | Autoprotección (anti-tamper), self-defense, cadena de confianza |
| [`docs/roadmap.md`](docs/roadmap.md) | Fases MVP → Beta → 1.0 → Enterprise + roadmap a 5 años |
| [`docs/estructura-carpetas.md`](docs/estructura-carpetas.md) | Estructura de carpetas del monorepo |

## Estado del código (MVP funcional)

Además del diseño, este repositorio incluye un **MVP funcional y probado** del núcleo:

| Componente | Lenguaje | Estado | Ubicación |
|------------|----------|--------|-----------|
| Agente / motor de detección híbrido | Rust (sin dependencias externas) | ✅ compila y pasa 31 tests | `endpoint/agent-core/` |
| Servicio de reputación en la nube | Go (stdlib) | ✅ compila y pasa tests | `cloud/reputation/` |
| Base de firmas | texto auditable | ✅ | `shared/signatures/base.db` |
| CI (fmt + clippy + tests + build) | GitHub Actions | ✅ | `.github/workflows/ci.yml` |

Lo que el motor **ya hace hoy** (extremo a extremo):

- **SHA-256** propio (streaming, verificado contra vectores FIPS 180-4).
- **Firmas** por hash y por patrón de bytes (YARA-lite).
- **Heurística** estática: entropía de Shannon + indicadores (ransomware, keylogger, inyección…).
- **Reputación**: caché local (offline) + cliente HTTP a la nube.
- **Motor de decisión**: fusión ponderada de señales con veto por firma → `LIMPIO / SOSPECHOSO / MALICIOSO`.
- **Escaneo incremental**: índice `(mtime,size,hash,verdict)` que salta ficheros no modificados.
- **Cuarentena**: aísla, ofusca y permite restaurar/eliminar.
- **CLI**: `scan`, `quick`, `selftest`, `quarantine`, `status`, `version`.
- **Anti-envenenamiento** en la nube: reportar un hash muchas veces nunca lo promueve a "bueno".

### Interfaz gráfica (programa de escritorio)

El agente incluye una **interfaz gráfica limpia** con barra de opciones lateral (Panel, Escáner,
Detecciones, Cuarentena, Herramientas, Ajustes), medidor de puntuación de protección y **modo oscuro**.

Funciones del escáner:
- **Escaneo rápido**: zonas de alto riesgo (temporales, descargas, autoarranque) **+ procesos en
  ejecución** (escaneo de la CPU).
- **Escaneo profundo**: todo el sistema/disco + procesos, con análisis exhaustivo de virus, troyanos,
  rootkits, keyloggers, mineros y backdoors.
- **Barra de progreso con porcentaje** en tiempo real (medidor circular + barra + fichero actual +
  contadores de amenazas), servida por trabajos en segundo plano (`/api/scan/start` +
  `/api/scan/progress`).
- **Auto-actualización de firmas** desde la nube (`/api/update`; auto-check al arrancar si hay
  servidor configurado). El servicio Go sirve el canal en `/v1/signatures`.

Se sirve como una SPA embebida en el propio binario y se abre en el navegador:

```bash
ngav serve            # abre http://127.0.0.1:8777 en el navegador
```

### Ejecutable de Windows (.exe)

Se cross-compila un `.exe` autocontenido desde Linux (la UI va embebida en el binario):

```bash
# Requisitos: rustup target add x86_64-pc-windows-gnu  +  apt install gcc-mingw-w64-x86-64
bash infra/ci/build-windows.sh
#   -> dist/NGAV-Windows/NGAV.exe  (+ signatures.db + "Iniciar NGAV.bat")
```

En Windows basta con hacer doble clic en **«Iniciar NGAV.bat»** (o ejecutar `NGAV.exe serve`) para
abrir la interfaz gráfica.

### Cómo ejecutarlo (CLI)

```bash
# 1) Autotest del motor con el fichero de prueba estándar EICAR
make selftest
#   -> RESULTADO: OK — el motor detecta correctamente EICAR.

# 2) Escanear un directorio (recursivo + incremental) y poner en cuarentena
cd endpoint/agent-core && cargo build --release
./target/release/ngav scan /ruta/a/escanear --quarantine

# 3) Con reputación en la nube
cd cloud/reputation && go run .            # levanta el servicio en :8080
./target/release/ngav scan /ruta --cloud http://127.0.0.1:8080

# 4) Todo (build + tests de Rust y Go)
make            # equivale a: make build test
```

> **Nota de alcance:** el MVP implementa las capas que funcionan íntegramente en espacio de usuario
> y multiplataforma. Los drivers de kernel, el sandbox, el ML/IA y el pipeline MLOps completos están
> **diseñados** en `docs/` y planificados por fases en `docs/roadmap.md`; el código aquí es la base
> sólida sobre la que se construyen.

## Resumen ejecutivo

**Objetivo:** detectar malware conocido y desconocido (zero-day), ransomware antes del cifrado,
spyware, troyanos, rootkits y keyloggers; aprender de nuevas amenazas sin depender solo de firmas;
minimizar falsos positivos; y mantener un impacto muy bajo en el rendimiento.

**Estrategia central:** un **motor de detección híbrido de defensa en profundidad** que combina ocho
técnicas complementarias, orquestadas por un motor de decisión que pondera el veredicto de cada capa.
El aprendizaje continuo se realiza **en la nube** (nunca entrenando modelos directamente en el
endpoint con datos no validados), con validación humana y automática antes de promover cualquier
modelo, protegiendo el sistema contra envenenamiento de datos (*data poisoning*) y ataques
adversariales.

**Principio ético y de privacidad:** telemetría minimizada, con consentimiento, anonimizada y
alineada con GDPR/CCPA. El producto se diseña para **defensa**, con transparencia sobre qué datos se
recopilan y por qué.
