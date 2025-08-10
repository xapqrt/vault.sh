Write-Host "[vault.sh] One-click local dev setup"
$ErrorActionPreference = 'Stop'
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Error "Python 3 not found"; exit 1 }
if (-not (Test-Path .venv)) { Write-Host "Creating virtual env (.venv)"; python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip | Out-Null
Write-Host "Installing deps..."; pip install -q -r config/requirements.txt | Out-Null
Write-Host "Smoke test..."; python -m src.main --help | Out-Null
Write-Host "Done. Try: python -m src.main init"
