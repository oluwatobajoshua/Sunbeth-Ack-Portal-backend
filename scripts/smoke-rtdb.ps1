param(
  [Parameter(Mandatory=$true)] [string]$BaseUrl,
  [string]$Token
)

# Simple smoke test for health and DB diag on a production environment
# Usage:
#   ./scripts/smoke-rtdb.ps1 -BaseUrl "https://<your-vercel-domain>" [-Token "<bypass-token>"]

function Invoke-Api {
  param(
    [string]$Path
  )
  $uri = "$BaseUrl$Path"
  $headers = @{}
  if ($Token) { $headers["x-bypass-token"] = $Token }
  try {
    $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -TimeoutSec 20
    return $resp
  } catch {
    Write-Host "Request failed: $uri" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor DarkRed
    if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
      $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
      $body = $reader.ReadToEnd()
      Write-Host $body -ForegroundColor DarkGray
    }
    throw
  }
}

Write-Host "Checking /api/health..." -ForegroundColor Cyan
$health = Invoke-Api "/api/health"
if (-not $health.ok) { throw "Health check failed" }
Write-Host "Health OK" -ForegroundColor Green

Write-Host "Checking /api/diag/db..." -ForegroundColor Cyan
$db = Invoke-Api "/api/diag/db"
if ($db.driver -ne "rtdb") {
  Write-Host (ConvertTo-Json $db -Depth 8) -ForegroundColor Yellow
  throw "Expected driver=rtdb, got '$($db.driver)'"
}
Write-Host "DB diag OK (driver=rtdb)" -ForegroundColor Green

Write-Host "Smoke complete." -ForegroundColor Green
