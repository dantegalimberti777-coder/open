# Etapa 1 — Fundaciones + Protección en tiempo real

> Estado: **implementada y validada** (Linux). Windows: compilado y listo para
> validar en tu equipo (usa ReadDirectoryChangesW vía `notify`).

Esta etapa incorpora la **protección en tiempo real (on-access)** y sienta las
bases de seguridad y desacoplo para el resto de la evolución, **sin eliminar ni
romper nada** de lo existente.

## 1. Qué se añadió

1. **Protección en tiempo real** (`src/realtime.rs`): vigila creación,
   modificación y renombrado de ficheros en las zonas de riesgo y los analiza
   **apenas aparecen**, sin escaneos manuales. Auto-cuarentena de lo malicioso.
2. **Endurecimiento de seguridad de la API local** (`src/server.rs`):
   validación de `Host`/`Origin` (bloquea CSRF / DNS-rebinding desde el
   navegador) y tope de tamaño de cuerpo (anti-DoS de memoria).
3. **UI**: interruptor real de protección en tiempo real (antes era un
   indicador fijo) y **línea temporal de amenazas** en Detecciones.
4. **Corrección de falso positivo**: la firma EICAR por patrón ahora exige la
   cadena completa del fichero de prueba (no sólo "EICAR").

## 2. Arquitectura y decisiones (SOLID / Clean)

### 2.1 Inversión de dependencias
`RealtimeService` **no conoce** el motor de detección: recibe una *callback*
`ScanCallback = Arc<dyn Fn(&Path) -> Option<ScanOutcome> + Send + Sync>`. El
servidor construye esa callback reutilizando el `Engine` existente (sin duplicar
la lógica de detección). Beneficios:

- **Testeable** con un escáner falso (los tests no dependen del SO ni del motor).
- **Sin acoplamiento**: mañana el mismo servicio puede dispatchar al futuro
  `Detector`/motor de comportamiento sin cambiar `realtime.rs`.
- **Sin duplicación**: la detección sigue viviendo en `engine.rs` (una sola
  fuente de verdad).

### 2.2 Flujo interno

```
notify (inotify/ReadDirectoryChangesW/FSEvents)
      │  evento del kernel (Create/Modify/Rename)
      ▼
[filtros baratos]  exclusiones · debounce por ruta · tamaño máx · tipo fichero
      │  (sólo lo que pasa)
      ▼
ScanCallback ──► Engine.scan_path ──► Veredicto
      │                                  │ MALICIOSO
      │                                  ▼
      │                            Quarantine (aísla)
      ▼
[buffer circular de eventos]  ──►  /api/realtime/events  ──►  UI (timeline)
[stats: scanned/detected/quarantined]
```

### 2.3 Rendimiento
- **Basado en eventos del kernel** (no polling) → CPU ~0 en reposo (cumple el
  SLO de <2 %).
- **Debounce por ruta** (800 ms por defecto): agrupa ráfagas de escrituras en un
  único análisis (verificado en test).
- **Filtros antes de tocar disco**: exclusiones por substring, tamaño máximo
  (128 MB), sólo ficheros regulares.
- **Búfer circular acotado** (200 eventos) para la línea temporal.

## 3. API nueva

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/realtime` | Estado (running, started_at, scanned, detected, quarantined) |
| GET | `/api/realtime/events` | Últimos eventos (línea temporal) |
| POST | `/api/realtime/start` | Activa la protección (respeta licencia) |
| POST | `/api/realtime/stop` | Desactiva la protección |

`/api/status` ahora incluye `"realtime": true|false`. La protección se **activa
por defecto** al arrancar si la licencia lo permite.

## 4. Dependencias introducidas

| Crate | Uso | Justificación |
|-------|-----|---------------|
| `notify` = 8 | Vigilancia FS multiplataforma | inotify (Linux), ReadDirectoryChangesW (Windows), FSEvents (macOS); basado en eventos del kernel; **cross-compila a Windows** (verificado) |

Supply-chain: `Cargo.lock` versionado. Próximas etapas añadirán `cargo-deny`.

## 5. Seguridad (riesgos corregidos y residuales)

**Corregido en esta etapa:**
- **CSRF / DNS-rebinding** contra la API local → rechazo por `Host`/`Origin` no
  locales (403). Verificado (`Host: evil.com` → 403, `Origin: http://evil.com`
  → 403).
- **DoS de memoria** por `Content-Length` gigante → tope de 1 MiB.
- **Falso positivo** de la firma EICAR por patrón.
- **Auto-escaneo/bucle**: se excluye la carpeta de datos del propio agente
  (cuarentena, journal, índice) de la vigilancia.

**Residual (planificado para Etapa 7 — Autoprotección):**
- Un **proceso local** con permisos aún podría hablar con la API (la validación
  de `Host`/`Origin` sólo detiene el vector navegador). La mitigación completa
  (token de sesión + verificación de identidad del proceso llamante) va con la
  autoprotección.
- Transporte a la nube aún en HTTP plano (TLS/firma → Etapa 7).

## 6. Pruebas

- **Unitarias** (`realtime.rs`): detección en tiempo real de un fichero
  malicioso recién creado; respeto de debounce en ráfaga; `start` idempotente y
  `stop` correcto. (3 tests, incluidos en los 50 del agente.)
- **Integración manual (E2E) verificada**: EICAR creado en `~/Downloads` →
  detectado y puesto en cuarentena automáticamente; fichero limpio ignorado;
  seguridad `Host`/`Origin` → 403.

## 7. Limitaciones conocidas

- En Linux, el conjunto de zonas vigiladas incluye `/tmp`; en un sistema con
  árboles enormes la **inscripción recursiva** de watches puede ser costosa. En
  Windows/macOS las zonas equivalentes (`%TEMP%`, Descargas, etc.) son de tamaño
  normal. Futuro: watches selectivos + presupuesto de watches.
- La ejecución de ficheros (evento *exec*) aún no se intercepta a nivel de
  proceso; llega con el **motor de comportamiento** (Etapa 2, ETW/eBPF).

## 8. Compatibilidad

- CLI, API previa y UI **siguen funcionando igual**. No se eliminó ni reemplazó
  ningún módulo. El `Engine` de detección es el mismo (reutilizado).

## 9. Roadmap inmediato (siguiente etapa)

**Etapa 2 — Motor de comportamiento**: grafo por proceso, indicadores ATT&CK
(inyección, hollowing, LSASS, AMSI/Defender bypass, LOLBins, persistencia) y
puntuación de riesgo acumulativa, alimentado por un sensor de procesos (ETW en
Windows, eBPF/proc en Linux). El `RealtimeService` ya está preparado para
dispatchar estos eventos sin cambios estructurales.
