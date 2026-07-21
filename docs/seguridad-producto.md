# Seguridad del Producto — Autoprotección (Anti-Tamper)

Un antivirus es un **objetivo prioritario** del malware: el primer paso de muchas amenazas es
desactivar o cegar la protección. El agente debe protegerse a sí mismo con la misma seriedad con la
que protege al sistema. Además, al correr con máximos privilegios, **no debe convertirse él mismo en
un vector de ataque**.

---

## 1. Modelo de amenazas del propio AV

Un atacante con privracia de usuario o administrador intentará:

- Matar el proceso/servicio del AV.
- Detener o deshabilitar el servicio y los drivers.
- Borrar/renombrar/corromper binarios, firmas, cuarentena o configuración.
- Modificar claves de registro/plists/units de arranque.
- Inyectar código en el proceso del AV o *hookear* sus llamadas.
- Suplantar actualizaciones (servidor falso) o forzar rollback a versión vulnerable.
- Cegar la telemetría (bloquear la conexión a la nube).
- Explotar una vulnerabilidad del propio agente (parser de ficheros, driver).

---

## 2. Defensas de autoprotección

### 2.1 Protección de procesos y servicios

- **Windows: Protected Process Light (PPL)** con **ELAM** (Early Launch Anti-Malware): el servicio
  arranca como *anti-malware protected*, de modo que ni siquiera un administrador puede terminarlo o
  inyectarlo fácilmente; solo código firmado por Microsoft/anti-malware puede tocarlo.
- **Vigilancia mutua (watchdog):** el servicio y un componente de kernel se **vigilan mutuamente**; si
  uno cae o es manipulado, el otro lo reinicia y registra el intento.
- **Driver de minifilter/callbacks de kernel** que **deniega** operaciones de terminación, apertura
  con permisos de escritura o inyección contra los procesos protegidos (ObRegisterCallbacks).
- macOS: EndpointSecurity + servicio con *SIP*/entitlements; Linux: capacidades restringidas + eBPF LSM
  para bloquear señales/ptrace contra el agente.

### 2.2 Protección de ficheros, configuración y registro

- Los binarios, bases de firmas, modelos, cuarentena y configuración se protegen contra
  escritura/borrado mediante el driver de kernel (filtro de FS y de registro).
- **Verificación de integridad continua:** hashes/firmas de los propios componentes se comprueban al
  arrancar y periódicamente; corrupción → auto-reparación desde copia protegida o re-descarga firmada.
- Cuarentena **cifrada** para que el malware aislado no pueda ejecutarse ni ser leído trivialmente.

### 2.3 Cadena de confianza y arranque seguro

- **Firma de código** de todos los binarios y drivers (EV cert); el SO solo carga drivers firmados.
- **ELAM/Secure Boot** garantiza que el AV se cargue **antes** que la mayoría del malware.
- **Anti-rollback** y **TUF** en actualizaciones (ver `arquitectura.md` §8): impide que un atacante
  instale una versión antigua vulnerable o un paquete no firmado.
- **Certificate pinning** en la comunicación con la nube: evita servidores de actualización falsos
  (MITM).

### 2.4 Protección de la comunicación y la telemetría

- **mTLS** con certificado por dispositivo; el backend rechaza clientes no autenticados.
- Si el malware bloquea la conexión, el endpoint **sigue protegiendo offline** y marca el estado como
  "conectividad degradada" (alerta en el panel empresarial).
- Detección de manipulación de red local (hosts file, proxy, DNS) que intente cegar el AV.

### 2.5 Reducir la superficie de ataque del propio agente

- **Núcleo en Rust** → elimina clases de vulnerabilidades de memoria en el código más expuesto
  (parsers de ficheros no confiables).
- **Aislamiento de parsers:** el análisis de ficheros no confiables se hace en procesos **con
  privilegios mínimos y sandboxed** (separación de privilegios), de modo que un exploit del parser no
  otorgue SYSTEM.
- **Principio de mínimo privilegio:** la UI no tiene privilegios; cada componente solo los permisos que
  necesita.
- **SDLC seguro:** revisión de código, *fuzzing* continuo de parsers, SAST/DAST, pentesting, programa
  de *bug bounty*, y respuesta rápida a vulnerabilidades del propio producto.
- **Verificación de la UI:** el servicio solo acepta comandos de una UI cuyo binario esté firmado y
  autorizado (evita que malware suplante la UI para dar órdenes).

### 2.6 Resiliencia y recuperación

- **Modo a prueba de fallos:** si un componente es manipulado, el agente entra en un estado seguro
  (mantiene bloqueo por defecto) en lugar de "abrir".
- **Auto-reparación:** reinstalación de componentes corruptos desde origen firmado.
- **Alertas de manipulación:** todo intento de tamper genera evento de alta prioridad al panel/SIEM.

---

## 3. Gobernanza y confianza

- **Actualizaciones firmadas + transparencia** (transparency log) para que un compromiso interno sea
  detectable.
- **Separación de deberes** en la publicación de modelos/firmas (nadie publica solo; se requiere
  aprobación).
- **Auditoría inmutable** de acciones administrativas y de promoción de modelos.
- **Divulgación responsable:** proceso claro para reportar vulnerabilidades del producto.
