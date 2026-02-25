Param(
  [Parameter(Mandatory=$true)][int]$Port,
  [string]$RuleName = "Allow Node Port"
)

Write-Host "Opening Windows Firewall for TCP port $Port..."
try {
  New-NetFirewallRule -DisplayName "$RuleName $Port" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Firewall rule ensured for port $Port."
} catch {
  Write-Warning "Failed to create firewall rule: $($_.Exception.Message)"
}

Write-Host "Testing localhost connectivity..."
try {
  $ok = (Test-NetConnection -ComputerName localhost -Port $Port).TcpTestSucceeded
  Write-Host ("TcpTestSucceeded: {0}" -f $ok)
  if (-not $ok) {
    Write-Host "Tip: ensure the server is running and bound to localhost."
  }
} catch {
  Write-Warning "Connectivity test failed: $($_.Exception.Message)"
}
