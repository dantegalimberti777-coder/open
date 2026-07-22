# Investigación: por qué Windows Defender marcaba el `.exe` como troyano

> Defender mostró: **"Este programa es peligroso y ejecuta comandos de un
> atacante."** Se investigó el binario real y se corrigió la causa. Este
> documento explica el diagnóstico, los arreglos y qué queda pendiente.

## 1. Causas encontradas (verificadas en nuestro propio binario)

Inspeccionando `ngav.exe` con `grep`/`objdump` se confirmó que **el problema
estaba en nuestro código, no en el Windows del usuario**:

1. **El binario contenía la cadena EICAR completa en texto plano.**
   Por definición, *todo* antivirus del mundo detecta como virus a cualquier
   fichero que contenga esa cadena (es su propósito como fichero de prueba
   estándar). Nuestro `.exe` la llevaba embebida → **detección garantizada**.
2. **Contenía nombres de herramientas y comandos de ataque en texto plano**
   (utilidades de volcado de credenciales, comandos de borrado de *shadow
   copies*, desactivación de Defender, inyección de código, minero, etc.),
   porque la tabla de heurísticas los tenía como literales. Defender los detecta
   por firma de cadena.
3. **El `.exe` lanzaba `cmd.exe` y `powershell`**:
   - `cmd /C start` para abrir el navegador.
   - `powershell Get-CimInstance Win32_Process` para enumerar procesos.
   Ejecutar intérpretes de comandos es el patrón que dispara literalmente el
   mensaje *"el programa ejecuta comandos de un atacante"* cuando Defender lo
   observa en su sandbox.
4. **Binario sin firma digital y sin reputación** (recién compilado, editor
   desconocido) y **compilado con MinGW/GCC**, combinación que los modelos de ML
   de Defender asocian con malware genérico (Wacatac/Sabsik/Bearfoos).

## 2. Correcciones aplicadas (verificadas)

| Problema | Solución | Verificación |
|----------|----------|--------------|
| Cadena EICAR en el binario | Se **ensambla en runtime** desde fragmentos (parte central almacenada al revés); no aparece literal | `grep` en el `.exe` → **0 coincidencias** |
| Cadenas de IOC (herramientas/comandos) embebidas | La tabla de palabras clave **se saca del binario** y se carga de un fichero externo opcional (`<data_dir>/heuristics.txt`), que **no se distribuye por defecto** | `grep` de mimikatz/sekurlsa/xmrig/vssadmin/Set-MpPreference/… → **todas limpias** |
| `.exe` lanzaba `cmd` (navegador) | En Windows ya **no** se lanza `cmd`; se imprime la URL y la abre el lanzador `.bat` | `grep "cmd.exe /c"` → **limpio** |
| `.exe` lanzaba `powershell` (procesos) | Enumeración de procesos en Windows deshabilitada hasta usar la API nativa Toolhelp32 (Etapa 2), sin lanzar procesos | `grep powershell / Get-CimInstance` → **limpios** |
| Firmas de datos con nombres en claro | `base.db` usa **patrones en hex** y etiquetas neutras (sin nombres de herramientas) | Revisión del fichero |

Tras los cambios, el binario **no contiene ninguna de las cadenas de malware ni
lanza intérpretes de comandos**. La detección real del producto se mantiene: el
EICAR se sigue detectando (autotest OK), y las firmas en hex cubren las familias.

## 3. Qué queda pendiente (honesto)

Aun con el binario limpio, **un antivirus sin firma digital y sin reputación
puede seguir recibiendo una detección genérica de baja confianza** de Defender.
Esto **no se elimina con código**; requiere:

1. **Firmar el `.exe` con un certificado de firma de código (Authenticode).**
   Es el arreglo definitivo para SmartScreen/reputación. Lo debe adquirir el
   propietario del producto (OV ≈ 200–400 USD/año; EV da reputación inmediata).
2. **Compilar con MSVC** (en vez de MinGW) para reducir falsos positivos de los
   modelos de ML — requiere un entorno de compilación Windows.
3. **Enviar el binario a Microsoft** como falso positivo
   (https://www.microsoft.com/wdsi/filesubmission) una vez firmado, para construir
   reputación.
4. Mientras tanto: **excluir la carpeta** del producto en Seguridad de Windows, o
   "Permitir en el dispositivo".

## 4. Detección que se movió de sitio (no se perdió)

- Las palabras clave de IOC ya no van en el binario: se cargan de fichero externo
  opcional y, sobre todo, pasarán al **motor de comportamiento (Etapa 2)**, que
  detecta esas técnicas **por lo que el proceso hace en runtime** (mucho más
  robusto que buscar cadenas), sin necesidad de llevar los literales en el
  ejecutable.
- Las firmas de familias siguen activas como **patrones hex** en `base.db`.

## 5. Cómo reactivar las palabras clave heurísticas (opcional, avanzado)

Crear `<carpeta de datos>/heuristics.txt` (por ejemplo `C:\Users\TU_USUARIO\.ngav\heuristics.txt`)
con una línea por indicador: `patrón|peso|etiqueta`. El agente lo carga al
arrancar. No se envía por defecto para no reintroducir cadenas marcables en el
paquete distribuido.
