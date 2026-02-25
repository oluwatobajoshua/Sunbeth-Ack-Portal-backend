Param(
  [int]$Port = 4116,
  [string]$BindHost = "localhost",
  [string]$Admin = "oluwatoba.ogunsakin@sunbeth.net"
)

Push-Location "$PSScriptRoot\.." # backend root
Write-Host "Starting modular server on ${BindHost}:${Port} (localhost enforced)..."

# Allow firewall for chosen port (idempotent)
try {
  New-NetFirewallRule -DisplayName "Allow Node $Port" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
} catch {}

$env:PORT = "$Port"
$env:HOST = "$BindHost"
$env:FORCE_SUPERADMIN_EMAILS = "$Admin"

# Stop any process currently listening on the chosen port (do NOT kill all node processes)
try {
  $conn = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
    Select-Object -First 1 -Property OwningProcess
  if ($conn -and $conn.OwningProcess) {
    Write-Host "Stopping existing process on port $Port (PID=$($conn.OwningProcess))..."
    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
  }
} catch {}

# Start backend in background so prestart can continue to React dev server
try {
  $wd = (Get-Location).Path
  Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory $wd -WindowStyle Hidden
  Write-Host "Backend start triggered (node server.js) in background."
} catch {
  Write-Warning "Failed to start backend in background: $($_.Exception.Message)"
}

# Quick health check (non-blocking)
try {
  Start-Sleep -Seconds 1
  $ok = (Test-NetConnection -ComputerName localhost -Port $Port).TcpTestSucceeded
  if ($ok) {
    Write-Host "Health: TCP port $Port is reachable on localhost."
  } else {
    Write-Warning "Health: TCP port $Port is NOT reachable yet."
  }
} catch {}
