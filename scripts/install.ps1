Param(
  [string]$Repo = 'xapqrt/vault.sh'
)
Write-Host "Installing vaultsh"
$ErrorActionPreference = 'Stop'
$api = "https://api.github.com/repos/$Repo/releases/latest"
$release = (Invoke-WebRequest -UseBasicParsing -Uri $api | ConvertFrom-Json)
$asset = $release.assets | Where-Object { $_.name -like 'vaultsh-windows*' } | Select-Object -First 1
if ($asset) {
  $out = Join-Path $env:TEMP 'vaultsh.exe'
  Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $out
  $dest = "$env:ProgramData\vaultsh"
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item $out (Join-Path $dest 'vaultsh.exe') -Force
  $pathAdd = "$dest"
  if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $pathAdd })) { Write-Host "Add $pathAdd to PATH manually if not picked up." }
  Write-Host "Installed vaultsh.exe to $dest"; & "$dest\vaultsh.exe" --help; exit 0
}
Write-Warning "Binary not found in latest release; falling back to source install."
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Error "git required for fallback"; exit 1 }
if (-not (Test-Path vault.sh)) { git clone https://github.com/$Repo.git vault.sh }
Set-Location vault.sh
if (-not (Test-Path .venv)) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
pip install -q -r config/requirements.txt
Write-Host "Run: python -m src.main --help"
