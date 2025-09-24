<#!
 Script de arranque del proyecto
 Uso:
   1. Abre PowerShell en la carpeta del proyecto (este archivo)
   2. (Opcional) Para esta sesión permitir scripts: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   3. Ejecuta: ./run.ps1
#>

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERR ] $msg" -ForegroundColor Red }

# 1. Verificar Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) { $pythonCmd = Get-Command py -ErrorAction SilentlyContinue }
if (-not $pythonCmd) {
    Write-Err "No se encontró Python en el PATH. Instala Python 3.11+ desde https://www.python.org/downloads/ y marca 'Add python to PATH'."
    exit 1
}
Write-Info "Usando Python: $($pythonCmd.Source)"

# 2. Crear entorno virtual si no existe
if (-not (Test-Path .venv)) {
    Write-Info "Creando entorno virtual (.venv)..."
    & $pythonCmd.Source -m venv .venv
} else { Write-Info ".venv ya existe" }

# 3. Activar entorno
$activate = Join-Path .venv 'Scripts/Activate.ps1'
if (-not (Test-Path $activate)) { Write-Err "No se encontró script de activación: $activate"; exit 1 }
Write-Info "Activando entorno virtual"
. $activate

# 4. Actualizar pip y dependencias
Write-Info "Actualizando pip"; python -m pip install --upgrade pip
Write-Info "Instalando dependencias"; pip install -r escaner/requirements.txt

# 5. Crear carpeta reports si falta
if (-not (Test-Path reports)) { New-Item -ItemType Directory reports | Out-Null }

# 6. Lanzar la aplicación Flask
Write-Info "Iniciando aplicación en http://127.0.0.1:5000"
python escaner/app.py
