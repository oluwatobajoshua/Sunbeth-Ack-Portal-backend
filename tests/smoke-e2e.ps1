Param(
  [string]$ApiBase = "http://127.0.0.1:4000",
  [string]$AdminEmail = $env:REACT_APP_SUPER_ADMINS,
  [string]$TestUser = ""
)

$ErrorActionPreference = "Stop"

function Fail($msg) { Write-Host "E2E FAIL: $msg" -ForegroundColor Red; exit 2 }
function Info($msg) { Write-Host "[E2E] $msg" -ForegroundColor Cyan }

# Normalize AdminEmail (pick first if comma-separated)
if (-not $AdminEmail -or $AdminEmail.Trim() -eq "") { Fail "AdminEmail not provided and REACT_APP_SUPER_ADMINS env not set." }
$AdminEmail = ($AdminEmail -split ',')[0].Trim()

# Generate a unique test user email if not provided
if (-not $TestUser -or $TestUser.Trim() -eq "") {
  $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $TestUser = "e2e.user.$epoch@sunbeth.net"
}

# 1) Health check
Info "Health check $ApiBase/api/health"
$health = Invoke-RestMethod -Uri ("{0}/api/health" -f $ApiBase)
if (-not $health.ok) { Fail "Health returned unexpected response: $($health | ConvertTo-Json -Compress)" }

# 2) Ensure we have a library file (upload a tiny PDF if needed)
Info "Ensuring library has at least one file"
$lib = Invoke-RestMethod -Uri ("{0}/api/library/list?limit=1" -f $ApiBase)
$fileId = $null
if ($lib.files -and $lib.files.Count -gt 0) {
  $fileId = [int]$lib.files[0].id
  Info ("Using existing file id {0}: {1}" -f $fileId, $lib.files[0].name)
} else {
  $pdfPath = Join-Path $PSScriptRoot 'tmp.pdf'
  $pdfContent = @" 
%PDF-1.4
1 0 obj
<<>>
endobj
trailer
<<>>
startxref
0
%%EOF
"@
  Set-Content -Path $pdfPath -Value $pdfContent -Encoding Ascii
  Info "Uploading a tiny placeholder PDF"
  $uploadJson = & curl.exe -s -F ("file=@{0};type=application/pdf" -f $pdfPath) ("{0}/api/files/upload" -f $ApiBase) | ConvertFrom-Json
  if (-not $uploadJson.id) { Fail ("Upload failed: {0}" -f ($uploadJson | ConvertTo-Json -Compress)) }
  $fileId = [int]$uploadJson.id
  Info ("Uploaded file id {0}" -f $fileId)
}

# 3) Set legal consent document to fileId
Info ("Setting legal consent fileId = {0}" -f $fileId)
$headers = @{ 'X-Admin-Email' = $AdminEmail; 'Content-Type' = 'application/json' }
$setLegal = Invoke-RestMethod -Method Put -Uri ("{0}/api/settings/legal-consent" -f $ApiBase) -Headers $headers -Body (@{ fileId = $fileId } | ConvertTo-Json -Compress)
if ($setLegal.fileId -ne $fileId) { Fail ("Set legal consent failed: {0}" -f ($setLegal | ConvertTo-Json -Compress)) }

# 4) Verify admin policies list accessible
Info "Listing admin policies"
$policies = Invoke-RestMethod -Uri ("{0}/api/admin/policies" -f $ApiBase) -Headers @{ 'X-Admin-Email' = $AdminEmail }
if ($policies -eq $null -or $policies.policies -eq $null) { Fail "Admin policies endpoint returned unexpected shape" }

# 5) Create a policy with this file
Info "Creating a test policy"
$createBody = @{ name = 'E2E Policy'; description = 'auto'; frequency = 'annual'; required = $true; fileIds = @($fileId); dueInDays = 30; graceDays = 0; active = $true } | ConvertTo-Json -Compress
$created = Invoke-RestMethod -Method Post -Uri ("{0}/api/admin/policies" -f $ApiBase) -Headers $headers -Body $createBody
if (-not $created.id) { Fail ("Create policy failed: {0}" -f ($created | ConvertTo-Json -Compress)) }
$policyId = [int]$created.id

# 6) Try to ack without consent for user (should be 403 legal_consent_required)
Info "Attempting ack without consent (expect 403)"
$ackBody = @{ email = $TestUser; fileId = $fileId } | ConvertTo-Json -Compress
$got403 = $false
try {
  $null = Invoke-RestMethod -Method Post -Uri ("{0}/api/policies/ack" -f $ApiBase) -ContentType 'application/json' -Body $ackBody -ErrorAction Stop
} catch {
  try {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 403) { $got403 = $true }
  } catch {}
  if (-not $got403) {
    try {
      $respStream = $_.Exception.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($respStream)
      $bodyText = $reader.ReadToEnd()
      $err = $null
      try { $err = $bodyText | ConvertFrom-Json } catch { $err = $bodyText }
      if ($err.error -eq 'legal_consent_required') { $got403 = $true }
    } catch {}
  }
}
if (-not $got403) { Fail "Ack did not return legal_consent_required as expected" }

# 7) Record consent for user
Info "Recording legal consent for test user"
$consent = Invoke-RestMethod -Method Post -Uri ("{0}/api/consents" -f $ApiBase) -ContentType 'application/json' -Body (@{ email = $TestUser } | ConvertTo-Json -Compress)
if (-not $consent.ok) { Fail ("Consent failed: {0}" -f ($consent | ConvertTo-Json -Compress)) }

# 8) Ack again (should succeed)
Info "Acknowledging policy after consent"
$ack = Invoke-RestMethod -Method Post -Uri ("{0}/api/policies/ack" -f $ApiBase) -ContentType 'application/json' -Body $ackBody
if (-not $ack.ok) { Fail ("Ack failed: {0}" -f ($ack | ConvertTo-Json -Compress)) }

# 9) Due list should not include our just-acked policy/file for this user
Info "Checking due policies for user"
$due = Invoke-RestMethod -Uri ("{0}/api/policies/due?email={1}" -f $ApiBase, [uri]::EscapeDataString($TestUser))
if (-not $due.due) { Fail ("Due endpoint returned unexpected payload: {0}" -f ($due | ConvertTo-Json -Compress)) }
$mine = @($due.due | Where-Object { $_.fileId -eq $fileId -and $_.name -eq 'E2E Policy' })
if ($mine.Count -gt 0) { Fail ("Our policy/file still due after ack: {0}" -f (($mine | ConvertTo-Json -Compress))) }

# 10) Cleanup: delete policy
Info ("Deleting policy id {0}" -f $policyId)
$del = Invoke-RestMethod -Method Delete -Uri ("{0}/api/admin/policies/{1}" -f $ApiBase, $policyId) -Headers @{ 'X-Admin-Email' = $AdminEmail }
if (-not $del.ok) { Fail ("Delete policy failed: {0}" -f ($del | ConvertTo-Json -Compress)) }

Write-Host "E2E PASS" -ForegroundColor Green
exit 0
