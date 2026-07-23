# Investigación de amenazas modernas y diseño del motor de detección (NGAV/EDR/XDR)

> **Naturaleza del documento.** Especificación técnica **defensiva**. Describe las
> amenazas al nivel que un defensor necesita para **detectarlas, prevenirlas,
> responder y recuperarse**. No contiene instrucciones operativas para crear
> malware ni para evadir controles de seguridad: cada técnica ofensiva se presenta
> únicamente por sus **señales observables** y por **cómo el producto la detecta**.
>
> **Estado del proyecto (mapa honesto).** El NGAV ya tiene implementado y probado
> un núcleo real: motor híbrido de decisión, firmas (hash + patrones), heurística
> + entropía, análisis estático PE/ELF/Mach-O (`goblin`), motor de comportamiento
> MITRE ATT&CK (noisy-OR), protección en tiempo real (`notify`), reputación
> local/nube, cuarentena, optimizador y GUI. Lo que este documento añade es la
> **hoja de ruta completa** hacia una plataforma empresarial: para cada capacidad
> se indica si está **[HECHO]**, **[PARCIAL]** o **[ROADMAP]**, con qué módulo la
> cubre y qué límites reales tiene. No se promete lo que no se ha construido.

Índice:

1. Taxonomía de malware y su detección
2. Técnicas de evasión y su detección
3. Persistencia y su detección
4. Rootkits y su detección
5. Motores de detección (arquitectura por capas)
6. IA aplicada al antivirus
7. Catálogo de módulos del producto
8. Respuesta automática
9. Análisis forense
10. Arquitectura integrada y flujo de datos

---

## 1. Taxonomía de malware y su detección

Para cada familia: **qué es**, **vector de infección**, **cómo se oculta/propaga**,
y las **señales defensivas** con las que el NGAV lo detecta. La columna final ata
cada familia a los módulos del producto (§7).

### 1.1 Código autorreplicante clásico

| Familia | Concepto | Señales de detección | Módulo NGAV |
|---|---|---|---|
| **Virus** | Se inserta en ficheros/host legítimos y se ejecuta al abrirlos. | Cambio de hash de binarios firmados; secciones ejecutables añadidas; punto de entrada alterado; entropía anómala. | Firmas [HECHO], estático [HECHO], integridad de ficheros [ROADMAP] |
| **Gusano (worm)** | Se propaga solo por red/USB sin acción del usuario. | Ráfagas de conexiones salientes a rangos amplios (SMB/445, RDP/3389); escaneo de puertos; escritura masiva en unidades extraíbles. | Motor de red [ROADMAP], protección USB [ROADMAP], comportamiento [PARCIAL] |
| **Troyano** | Se hace pasar por software legítimo; entrega una carga oculta. | Binario no firmado que imita a uno conocido; entropía alta + overlay grande; discrepancia icono/nombre/metadatos PE; comportamiento post-ejecución. | Estático [HECHO], reputación [HECHO], comportamiento [PARCIAL] |

### 1.2 Extorsión y destrucción

- **Ransomware** — cifra datos y exige pago. **Señales**: apertura+lectura+
  escritura+renombrado en ráfaga sobre muchos ficheros de usuario; caída de
  entropía→subida de entropía por fichero (texto→cifrado); borrado de *shadow
  copies* (T1490); creación de notas de rescate; llamadas masivas a APIs de
  criptografía. **Módulo**: motor de comportamiento (indicadores
  `MassFileEncryption` T1486, `ShadowCopyDeletion` T1490) **[PARCIAL]** + honeypots
  de ficheros señuelo y *rollback* desde copias **[ROADMAP]**.
- **Wiper** — destruye datos sin rescate (sabotaje). **Señales**: sobrescritura de
  MBR/GPT; borrado masivo irreversible; acceso directo a `\\.\PhysicalDrive`.
  **Módulo**: protección de arranque + comportamiento **[ROADMAP]**.
- **Logic bomb** — carga latente que dispara por condición (fecha, evento).
  **Señales**: comprobaciones de fecha/entorno seguidas de acción destructiva;
  código inalcanzable en análisis estático. **Módulo**: sandbox + estático **[ROADMAP]**.

### 1.3 Espionaje y robo

- **Spyware / Keylogger / Screenlogger / Clipboard hijacker** — capturan
  pulsaciones, pantalla o portapapeles. **Señales**: instalación de *hooks* de
  teclado/ratón de bajo nivel (`SetWindowsHookEx`), lectura periódica del
  portapapeles, capturas de pantalla programadas, exfiltración periódica.
  **Módulo**: comportamiento (`CredentialAccess`, captura) **[PARCIAL]** + protección
  de portapapeles/entrada **[ROADMAP]**.
- **RAT (troyano de acceso remoto)** — control remoto interactivo. **Señales**:
  *beaconing* periódico a C2, canal de mando persistente, ejecución de comandos
  bajo demanda. **Módulo**: red (detección de *beaconing*) **[ROADMAP]** + comportamiento.
- **Botnet** — red de equipos controlados. **Señales**: tráfico a
  infraestructura C2 conocida, DGA (dominios generados algorítmicamente),
  sincronización de actividad. **Módulo**: red + inteligencia de amenazas **[ROADMAP]**.
- **Browser hijacker / Adware** — alteran navegador/inyectan anuncios.
  **Señales**: cambios no autorizados de página de inicio/motor de búsqueda,
  extensiones no solicitadas, inyección en procesos de navegador.
  **Módulo**: protección de navegador **[ROADMAP]**.
- **Cryptominer** — usa CPU/GPU para minar. **Señales**: uso sostenido de
  CPU/GPU, conexiones a *pools* de minería, procesos ocultos de larga duración.
  **Módulo**: comportamiento + red **[ROADMAP]**.

### 1.4 Sigilo profundo (nivel firmware/kernel)

- **Rootkit** — oculta su presencia manipulando el SO (ver §4).
- **Bootkit** — infecta el arranque (MBR/VBR/bootloader) para cargar antes del SO.
  **Señales**: modificación de MBR/GPT, componentes EFI no firmados en la ESP.
  **Módulo**: escáner de arranque/UEFI **[ROADMAP]**.
- **Malware de firmware / UEFI** — persiste en la SPI flash o en la ESP, sobrevive
  a reinstalaciones. **Señales**: entradas no firmadas en `\EFI\`, drivers DXE
  desconocidos, discrepancias con listas de permitidos del fabricante.
  **Módulo**: escáner UEFI/ESP **[ROADMAP]** — límite honesto: requiere acceso
  privilegiado a la ESP y, para la SPI flash, cooperación del hardware; en modo
  usuario sólo se auditan los artefactos de la partición EFI.

### 1.5 Malware sin fichero y "vivir de la tierra"

- **Fileless** — reside en memoria/registro/WMI, no toca disco como ejecutable.
  **Señales**: código ejecutándose desde regiones de memoria sin respaldo en
  disco (RWX/privado), payloads en claves de registro, suscripciones WMI.
  **Módulo**: escáner de memoria **[ROADMAP]** + comportamiento **[PARCIAL]**.
- **Living Off The Land (LOLBins)** — abusa de binarios legítimos del SO para
  fines maliciosos. **Señales**: **cadenas de proceso anómalas** (un binario de
  ofimática lanzando un intérprete que a su vez descarga y ejecuta), argumentos
  ofuscados, uso de utilidades administrativas fuera de contexto. **Enfoque
  defensivo**: no se bloquea el binario legítimo, se puntúa la **secuencia**.
  **Módulo**: comportamiento (árbol de procesos) **[PARCIAL/ROADMAP]**.

### 1.6 Ofuscación y empaquetado

- **Polimórfico / Metamórfico** — cambian su código en cada muestra para eludir
  firmas. **Contramedida**: firmas por hash pierden eficacia → se pasa a
  **heurística estructural, comportamiento y ML**, que miran *qué hace* y *cómo
  está construido*, no bytes exactos. **Módulo**: estático + comportamiento + ML.
- **Packed / Crypter** — comprimen/cifran el código real y lo desempaquetan en
  memoria. **Señales**: entropía muy alta por sección, pocos o ningún *import*,
  secciones RWX, *overlay* grande. **Módulo**: análisis estático **[HECHO]** (ya
  emite estos indicadores) + desempaquetado en sandbox **[ROADMAP]**.
- **Dropper / Downloader** — instalan/descargan la carga real. **Señales**:
  escritura de un segundo ejecutable + su ejecución; descarga desde URL recién
  registrada; cadena padre-hijo sospechosa. **Módulo**: comportamiento + red.
- **Malware modular / con IA** — descargan capacidades a demanda o adaptan su
  comportamiento. **Señales**: carga dinámica de módulos, C2 que entrega tareas,
  comportamiento no determinista. **Módulo**: comportamiento + red + ML.

### 1.7 Cobertura por plataforma

| Plataforma | Particularidades de detección | Estado |
|---|---|---|
| **Windows** | PE, servicios, registro, WMI, ETW, LSASS, UAC. Núcleo del producto. | Estático PE [HECHO]; sensores ETW [ROADMAP] |
| **Linux** | ELF, `/proc`, cron, systemd, LD_PRELOAD, cgroups. | Estático ELF [HECHO]; sensor eBPF [ROADMAP] |
| **macOS** | Mach-O, LaunchAgents/Daemons, TCC, notarización. | Estático Mach-O [PARCIAL] |
| **Android / iOS** | APK/IPA, permisos, sideloading; móvil ≠ endpoint clásico. | [ROADMAP] — fuera del núcleo actual |
| **Servidores** | Superficie web, servicios expuestos, movimiento lateral. | Motor de red/HIDS [ROADMAP] |
| **Docker / Kubernetes** | Imágenes con CVE, *escapes* de contenedor, RBAC, *secrets*. | [ROADMAP] — módulo cloud-native separado |
| **NAS** | Firmware embebido, SMB/NFS, ransomware sobre recursos compartidos. | [ROADMAP] |

> **Honestidad de alcance.** El núcleo probado hoy es **Windows/Linux endpoint**.
> macOS es parcial (sólo estático). Móvil, contenedores y NAS son líneas de
> producto separadas en el roadmap, no capacidades ya presentes.

---

## 2. Técnicas de evasión y su detección

Se agrupan por objetivo defensivo. Para cada grupo: **qué buscan lograr los
atacantes** y **qué observa el defensor**. (Sin recetas de implementación.)

### 2.1 Inyección y ejecución en procesos ajenos

Incluye *process hollowing*, *process/DLL injection*, *reflective loading*, *APC
injection*, *thread hijacking*, *early bird*, *module stomping*, *PE injection*,
*AtomBombing*. **Objetivo del atacante**: ejecutar código dentro de un proceso
confiable para heredar su legitimidad y ocultarse.

**Señales de detección (comunes)**:
- Regiones de memoria **privadas con permiso de ejecución** (RWX o RX no
  respaldadas por un fichero en disco).
- Escritura en el espacio de memoria de **otro** proceso seguida de creación de
  hilo/cola APC/redirección del contexto de un hilo.
- Discrepancia entre la imagen mapeada en memoria y el fichero PE en disco
  (*hollowing*: la sección .text en memoria no coincide con el disco).
- Hilos cuyo punto de inicio cae en memoria sin módulo asociado.

**Módulo NGAV**: motor de comportamiento (`ProcessInjection` T1055) **[PARCIAL]** +
escáner de memoria que enumera regiones y compara imagen-en-memoria vs disco
**[ROADMAP]**. La fusión noisy-OR ya garantiza que **ninguna señal condena sola**.

### 2.2 Evasión de telemetría y controles

Incluye *ETW bypass*, *AMSI bypass*, desactivación de defensas (T1562), *API hook
bypass*, *direct/indirect syscalls*, *Heaven's/Hell's Gate*. **Objetivo**:
cegar los sensores del defensor.

**Señales**: parcheo en memoria de funciones de telemetría/escaneo (los primeros
bytes de una función crítica difieren de la imagen limpia del módulo);
resolución de servicios del sistema evitando las bibliotecas normales; intentos
de detener/alterar servicios de seguridad. **Módulo**: detección de *inline
hooks* / integridad de código en memoria + autoprotección **[ROADMAP]**; el
indicador `DefenseEvasion` T1562 ya existe en el comportamiento **[PARCIAL]**.

### 2.3 Anti-análisis (anti-VM/sandbox/debug/emulador)

**Objetivo**: comportarse de forma benigna cuando se sienten observados.
**Señales**: comprobaciones de artefactos de virtualización, *sleeps* largos o
*sleep obfuscation*, retrasos temporales, detección de depurador, ramas que sólo
se activan sin analista. **Contramedida defensiva**: sandbox con **entorno
realista** (usuario/ratón/teclado/procesos simulados, reloj acelerado) y
**detección de la propia evasión** como señal de sospecha — que un binario
*intente* detectar la sandbox ya es un indicador. **Módulo**: sandbox dinámica
**[ROADMAP]**.

### 2.4 Ofuscación de código y cadenas

*Packing*, *crypters*, *string/runtime encryption*, *API hashing*, *control flow
flattening*, *junk/dead code*, protectores comerciales. **Señales**: ya cubiertas
por el análisis estático (entropía, imports ausentes, secciones anómalas) y, en
ejecución, por el desempaquetado observable en sandbox y por el comportamiento
final (la ofuscación oculta el código, no *lo que hace*). **Módulo**: estático
**[HECHO]** + sandbox/comportamiento **[ROADMAP/PARCIAL]**.

### 2.5 Abuso de credenciales e identidad

*Credential/LSASS dumping*, *token stealing*, *pass-the-hash/ticket*, *golden/
silver ticket*, *Kerberoasting*, *UAC/privilege escalation*, abuso de WMI/SMB.
**Objetivo**: robar identidades y moverse lateralmente. **Señales**: acceso al
proceso que custodia credenciales, lectura de secretos del sistema, patrones de
autenticación anómalos, elevación inesperada. **Módulo**: protección de
credenciales/LSASS + comportamiento (`CredentialAccess` T1003) **[PARCIAL]**;
correlación de identidad y UEBA **[ROADMAP]**.

> **Principio transversal de detección.** Casi todas estas técnicas convergen en
> pocas **primitivas observables**: memoria ejecutable anómala, manipulación de
> otro proceso, parcheo de funciones críticas, cadenas de proceso improbables y
> acceso a secretos. El NGAV instrumenta **esas primitivas** en lugar de
> perseguir cada nombre de técnica por separado — así una técnica nueva que use
> las mismas primitivas también se detecta.

---

## 3. Persistencia y su detección

La persistencia deja **artefactos auditables**. El enfoque del NGAV es un
**inventario de puntos de autoarranque (ASEP)** que se enumera, se compara con una
línea base y se vigila en tiempo real; cada cambio se puntúa por sospecha.

| Categoría de persistencia | Artefacto a vigilar | Detección |
|---|---|---|
| Claves Run / Startup | `...\Run`, carpeta de inicio | Snapshot + vigilancia de cambios [ROADMAP] |
| Servicios / Drivers | servicios auto, drivers cargados | Inventario + firma del driver [ROADMAP] |
| Tareas programadas | Task Scheduler / cron / systemd | Enumeración + diff [ROADMAP] |
| Winlogon / Userinit / Shell | valores de arranque de sesión | Baseline + alerta [ROADMAP] |
| IFEO (Image File Execution Options) | *debuggers* inyectados | Detección de claves IFEO anómalas [ROADMAP] |
| WMI | consumidores/filtros permanentes | Enumeración WMI [ROADMAP] |
| COM hijacking | CLSID redirigidos | Diff de registro COM [ROADMAP] |
| BITS jobs | trabajos de transferencia persistentes | Enumeración BITS [ROADMAP] |
| Perfiles de PowerShell | `profile.ps1` | Integridad de fichero [ROADMAP] |
| Shell/Office/Browser add-ins | extensiones cargadas | Inventario de complementos [ROADMAP] |
| DLL/COM search-order hijacking | DLL en rutas de búsqueda | Verificación de ruta+firma [ROADMAP] |
| UEFI/EFI/firmware | entradas de arranque, ESP | Escáner de arranque [ROADMAP] |

**Estado**: hoy el producto vigila el sistema de ficheros en tiempo real
**[HECHO]** y enumera procesos **[PARCIAL, Linux]**. El **inventario ASEP
completo** es el siguiente gran módulo defensivo (alto valor, bajo riesgo de FP
porque describe, no bloquea por defecto).

---

## 4. Rootkits y su detección

**Concepto (defensivo)**: un rootkit manipula el SO para ocultar procesos,
ficheros, claves o conexiones. Cuanto más profundo actúa, más difícil es
confiar en las APIs normales para verlo.

| Tipo | Dónde actúa | Detección defensiva |
|---|---|---|
| **User-mode** | *hooks* en bibliotecas de usuario (IAT/inline) | Comparar tablas de import y primeros bytes de funciones con la imagen limpia del módulo |
| **Kernel-mode** | SSDT/Shadow-SSDT hooking, IRP hooking, DKOM, callbacks | **Detección cruzada**: comparar la vista de "alto nivel" (API) con una enumeración de "bajo nivel"; lo que aparece en una y no en la otra está oculto |
| **Hypervisor** | capa por debajo del SO | Difícil desde el propio SO; requiere medición externa / atestación |
| **Firmware/UEFI** | SPI flash / ESP | Auditoría de la ESP y comparación con listas del fabricante |

**Técnica central defensiva — *cross-view detection***: enumerar procesos,
ficheros, claves y conexiones por **dos caminos independientes** (uno de alto
nivel, otro más directo) y **marcar las discrepancias**. Un objeto que el SO
"no ve" pero que existe es la firma de un rootkit. Complementos: verificación de
integridad de SSDT/IAT/inline, y validación de que **todo driver cargado esté
firmado y sea conocido**.

**Estado**: **[ROADMAP]**. Límite honesto: la detección fiable de rootkits de
kernel/hypervisor requiere un **driver propio firmado** (o un sensor eBPF en
Linux) y, para firmware, cooperación del hardware. En modo usuario se cubren
los rootkits de user-mode y se levantan indicadores indirectos.

---

## 5. Motores de detección (arquitectura por capas)

La filosofía es **defensa en profundidad**: capas independientes cuyas señales se
**fusionan** en el motor de decisión. Ninguna capa decide sola (las firmas
confirmadas son el único veto duro).

```
                 ┌─────────────────────────────────────────────┐
   Fichero /     │            MOTOR DE DECISIÓN (fusión)         │→ LIMPIO /
   Proceso /     │   veto duro (firma)  +  media ponderada  +    │  SOSPECHOSO /
   Evento   ───▶ │   noisy-OR de indicadores  +  umbrales        │  MALICIOSO
                 └───────▲───────▲───────▲───────▲───────▲───────┘
                         │       │       │       │       │
     ┌───────────────────┴─┐ ┌───┴────┐ ┌┴─────┐ ┌┴─────┐ ┌┴────────────┐
     │ Firmas (hash+bytes) │ │Heuríst.│ │Estát.│ │Comport.│ │Reputación/  │
     │      [HECHO]        │ │+entropía│ │PE/ELF│ │ATT&CK  │ │Threat Intel │
     │                     │ │[HECHO] │ │[HECHO]│ │[PARCIAL]│ │[HECHO/RM]  │
     └─────────────────────┘ └────────┘ └──────┘ └────────┘ └─────────────┘
                                              ▲          ▲
                    ┌─────────────────────────┴───┐ ┌────┴───────────────┐
                    │ Escáner de memoria [ROADMAP] │ │ Sandbox  [ROADMAP] │
                    └──────────────────────────────┘ └────────────────────┘
                    ┌──────────────────────────────┐ ┌────────────────────┐
                    │ Motor de red / DNS [ROADMAP] │ │ ML / DL [ROADMAP]  │
                    └──────────────────────────────┘ └────────────────────┘
```

**Capas y estado**:

- **Firmas** (hash + patrones de bytes) — veto duro. Barato, cero-FP para lo
  conocido. **[HECHO]**.
- **Heurística + entropía** — estructura y contenido estáticos. **[HECHO]**.
- **Análisis estático PE/ELF/Mach-O** — secciones, imports, overlay, RWX,
  empaquetado. **[HECHO]** (`goblin`).
- **Comportamiento (MITRE ATT&CK)** — indicadores por proceso, fusión noisy-OR,
  explicable. **[PARCIAL]**: motor listo, faltan **sensores reales** (ETW/eBPF).
- **Reputación** — caché local + cliente de nube. **[HECHO]** local; nube
  **[PARCIAL]**.
- **Threat Intelligence / IOC** — VirusTotal, MalwareBazaar, AbuseIPDB, URLHaus,
  OTX, MISP; YARA y Sigma. **[ROADMAP]** — se integra como fuentes de reputación
  e IOC matching sobre eventos.
- **ML / Deep Learning** — clasificador de PE por características estáticas
  (primer modelo realista), detección de anomalías, reducción de FP. **[ROADMAP]**.
- **Escáner de memoria, Kernel monitor, Sandbox, Motor de red (DNS/TLS/HTTP),
  USB, arranque/UEFI/firmware** — **[ROADMAP]** por orden de valor/riesgo.
- **EDR/XDR** — el EDR es la suma de sensores locales + respuesta + telemetría;
  el XDR correlaciona a través de endpoints/red/identidad en la consola central.
  **[ROADMAP]** — la arquitectura ya está preparada (decisión desacoplada de
  sensores vía la abstracción de señales).

**Marcos de referencia**: MITRE **ATT&CK** para nombrar y cubrir técnicas;
MITRE **D3FEND** para catalogar las contramedidas; **YARA**/**Sigma** como
lenguajes de regla abiertos.

---

## 6. IA aplicada al antivirus

Enfoque realista y por fases (sin "IA mágica"). La IA es **una capa más** cuyo
score entra en la fusión, nunca un oráculo único.

**Fase 1 — ML estático supervisado [ROADMAP inmediato]**
- Entrada: características ya extraídas por el módulo estático (entropía por
  sección, tabla de imports, tamaño de overlay, flags, nº de secciones, etc.).
- Modelo: clasificador tabular (p. ej. gradient boosting) *malware vs benigno*.
- Salida: `Signal(Source::MachineLearning, score, explicación)`.
- **Explicabilidad**: importancia de características por predicción → el usuario
  ve *por qué* (p. ej. "imports ausentes + entropía 7.9 + overlay grande").

**Fase 2 — Detección de anomalías y secuencias [ROADMAP]**
- Modela el comportamiento **normal** de un endpoint y marca desviaciones (base
  para **UEBA**). Analiza **secuencias** de eventos (no eventos sueltos) para
  capturar cadenas de ataque.

**Fase 3 — Correlación, predicción y aprendizaje continuo [ROADMAP]**
- Correlación de eventos entre capas (endpoint↔red↔identidad) para el XDR.
- **Aprendizaje continuo** con reentrenamiento periódico y **feedback del
  analista** (cada FP/FN corrige el modelo).
- **Aprendizaje federado**: mejorar modelos con telemetría de muchos clientes
  **sin** mover datos crudos (privacidad por diseño).
- **Generación asistida de reglas**: de un cluster de muestras similares, proponer
  una regla YARA/Sigma candidata para revisión humana (nunca despliegue ciego).

**Principios**: (1) la IA **no** vetea sola; (2) toda decisión es **explicable**;
(3) se optimiza para **bajo FP** (un antivirus con FP se desinstala); (4) los
datos de telemetría se **minimizan y anonimizan**.

---

## 7. Catálogo de módulos del producto

Estado: **[HECHO] / [PARCIAL] / [ROADMAP]**. Prioridad = valor defensivo ÷ riesgo
de FP ÷ coste.

**Núcleo ya operativo**
- Motor de detección híbrido + decisión por fusión — **[HECHO]**
- Firmas, heurística, entropía, estático PE/ELF/Mach-O — **[HECHO]**
- Protección en tiempo real (FS watcher) — **[HECHO]**
- Motor de comportamiento ATT&CK (sin sensor de SO aún) — **[PARCIAL]**
- Reputación local + cliente nube — **[HECHO/PARCIAL]**
- Cuarentena + optimizador + GUI + autoactualización — **[HECHO]**

**Prevención (roadmap por prioridad)**
1. **Anti-ransomware** (honeypots, detección de cifrado masivo, rollback) — alto valor
2. **Escáner de memoria** (inyección, código sin fichero, hollowing) — alto valor
3. **Sensores de comportamiento reales** (ETW en Windows / eBPF en Linux) — habilita el EDR
4. **Inventario ASEP + vigilancia de persistencia** — alto valor, bajo FP
5. **Protección de exploits** (mitigaciones anti-explotación en procesos)
6. **Protección de credenciales / LSASS**
7. **Protección de scripts / PowerShell / WMI** (vía integración AMSI/ETW)
8. **Motor de red**: firewall inteligente, IDS/IPS/HIPS, DNS, inspección TLS/HTTP
9. **Sandbox** local y en nube (detonación con entorno realista)
10. **Protección web / navegador / phishing / DNS**
11. **Protección USB / RDP / SMB / correo / documentos Office**
12. **Protección de kernel / UEFI / firmware** (requiere driver firmado)
13. **Protección de portapapeles / cámara / micrófono / wallets-cripto**
14. **Cloud-native**: Docker / Kubernetes / Hyper-V / VMware — línea aparte

> Cada módulo del roadmap se implementará con la misma disciplina del núcleo:
> diseñar → implementar → **probar** → documentar → integrar como **señal** en la
> fusión, sin condenar por una sola capa y con foco en cero-FP.

---

## 8. Respuesta automática

La respuesta es **graduada y reversible por defecto**; las acciones destructivas
requieren confirmación o política explícita.

| Acción | Cuándo | Reversible | Estado |
|---|---|---|---|
| Poner fichero en **cuarentena** | veredicto malicioso | Sí (restaurar) | **[HECHO]** |
| **Finalizar** proceso malicioso | comportamiento malicioso confirmado | N/A | [ROADMAP] |
| **Eliminar persistencia** (claves/tareas/servicios/drivers) | ASEP malicioso | Sí (backup del artefacto) | [ROADMAP] |
| **Rollback** de ficheros cifrados | ransomware detectado | Sí (desde snapshot) | [ROADMAP] |
| **Restaurar** configuración/registro | manipulación detectada | Sí | [ROADMAP] |
| **Aislar el host de la red** | incidente grave | Sí (reconectar) | [ROADMAP] |
| **Crear backups/snapshots** automáticos | preventivo/programado | — | [ROADMAP] |

**Principio**: preferir **contención reversible** (cuarentena, aislamiento) sobre
destrucción; registrar toda acción para auditoría y permitir deshacer.

---

## 9. Análisis forense

Capacidad de **reconstruir qué pasó** tras un incidente, recolectando artefactos
del sistema (defensivo, no intrusivo).

- **Timeline unificada**: fusionar eventos de todas las fuentes por marca de tiempo.
- **Artefactos de ejecución/actividad** (Windows): Prefetch, Amcache, Shimcache,
  SRUM, USN Journal, MFT, registro, eventos del SO — enumeración y correlación.
- **Memoria RAM**: captura y análisis de regiones/procesos (integrable con marcos
  tipo Volatility) para hallazgos *fileless*.
- **Red**: registro de conexiones, DNS, IOC observados.
- **IOC / YARA**: barrido retrospectivo de indicadores sobre disco y memoria.
- **Cadena de custodia**: exportar hallazgos con hash e integridad para informes.

**Estado**: **[ROADMAP]**. Encaja de forma natural sobre la telemetría del EDR:
una vez existen los sensores, el forense es la vista histórica y correlacionada
de esa misma telemetría.

---

## 10. Arquitectura integrada y flujo de datos

**Flujo de un evento/fichero (extremo a extremo)**:

```
  [Sensores]  FS-watcher · proceso · memoria · red · identidad
       │  (eventos + ficheros)
       ▼
  [Triage barato]  ¿ejecutable? ¿conocido por hash? ¿reputación?
       │  (descarta lo evidente; escala lo dudoso)
       ▼
  [Capas de análisis]  firmas · estático · heurística · comportamiento ·
       │               memoria · sandbox · red · ML   (cada una → Signal)
       ▼
  [Motor de decisión]  veto duro (firma) + fusión ponderada + noisy-OR + umbrales
       │  → LIMPIO / SOSPECHOSO / MALICIOSO  (+ explicación)
       ▼
  [Respuesta]  cuarentena · matar proceso · limpiar persistencia · rollback ·
       │        aislar red   (graduada, reversible, auditada)
       ▼
  [Telemetría/Consola]  EDR local → XDR central: correlación multi-host,
                        políticas, inventario, informes, alertas, API/webhooks,
                        RBAC y auditoría   (privacidad: datos minimizados)
```

**Por qué esta arquitectura resiste a amenazas modernas**:
- **Por capas**: eludir una capa no basta; el atacante debe eludirlas *todas* a la
  vez sin disparar la fusión.
- **Basada en primitivas observables** (§2), no en nombres de técnica → cubre
  variantes y ataques nuevos que reutilizan las mismas primitivas.
- **Explicable y calibrada a bajo FP** → utilizable en producción real.
- **Desacoplada** (sensores ↔ decisión ↔ respuesta vía la abstracción de
  `Signal`/puertos) → se añaden capas sin reescribir el núcleo, y el mismo motor
  sirve para endpoint (EDR) y para correlación central (XDR).

**Ventajas y limitaciones (resumen honesto)**:
- *Ventajas*: núcleo real ya probado; diseño extensible; disciplina anti-FP;
  memory-safety (Rust) en el componente privilegiado.
- *Limitaciones actuales*: sin driver de kernel ni sensor ETW/eBPF todavía → el
  comportamiento depende de sensores por implementar; sandbox, red, memoria y
  forense son roadmap; firma de código del ejecutable pendiente (afecta a la
  confianza de Windows/Defender). Nada de esto se presenta como ya resuelto.

---

### Trazabilidad con el resto de la documentación

- `docs/evolucion/00-analisis-arquitectura.md` — análisis base y decisiones.
- `docs/evolucion/01-tiempo-real.md` — protección en tiempo real (implementada).
- `docs/evolucion/02-falsos-positivos-defender.md` — disciplina anti-FP.
- `docs/evolucion/03-motor-comportamiento.md` — motor ATT&CK (implementado).
- `docs/motor-deteccion.md` — motor híbrido de decisión.
- Este documento — investigación de amenazas + especificación de la plataforma.

> Documento vivo: se actualiza al cerrar cada etapa del roadmap, marcando qué
> pasa de **[ROADMAP]** a **[PARCIAL]** y de **[PARCIAL]** a **[HECHO]** conforme
> se implementa y **se prueba**.
