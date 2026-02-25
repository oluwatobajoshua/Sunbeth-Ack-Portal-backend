Param(
  [int]$Port = 4116,
  [string]$Admin = "oluwatoba.ogunsakin@sunbeth.net"
)

function Get-Json($url) {
  try {
    $res = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 8 -Headers @{ "x-admin-email" = $Admin }
    return $res | ConvertTo-Json -Depth 5
  } catch {
    return "ERROR: $($_.Exception.Message)"
  }
}

$base = "http://localhost:$Port" # always use localhost

Write-Host "Checking $base/api/health..."
Write-Output (Get-Json "$base/api/health")

Write-Host "Checking $base/api/admin/settings (GET)..."
Write-Output (Get-Json "$base/api/admin/settings")

Write-Host "Checking $base/api/flags/effective..."
Write-Output (Get-Json "$base/api/flags/effective")
