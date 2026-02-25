Param(
  [string]$LogPath = "$PSScriptRoot\..\logs\app.log"
)

Write-Host "Tailing logs: $LogPath"
if (-not (Test-Path $LogPath)) {
  Write-Host "Log file not found yet. Creating directory if needed..."
  $dir = Split-Path -Parent $LogPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  New-Item -ItemType File -Path $LogPath | Out-Null
}

Get-Content -Path $LogPath -Wait -Tail 200
