Param(
  [string]$ApiBase = "http://127.0.0.1:4000",
  [string]$AdminEmail = $env:REACT_APP_SUPER_ADMINS,
  [switch]$IncludeNetwork = $false
)

$ErrorActionPreference = "Stop"

function Info($msg) { Write-Host ("[E2E] {0}" -f $msg) -ForegroundColor Cyan }
function Pass($msg) { Write-Host ("PASS  {0}" -f $msg) -ForegroundColor Green }
function Fail($msg) { Write-Host ("FAIL  {0}" -f $msg) -ForegroundColor Red }

# Normalize AdminEmail (pick first if comma-separated)
if (-not $AdminEmail -or $AdminEmail.Trim() -eq "") {
  Write-Host "AdminEmail not provided and REACT_APP_SUPER_ADMINS env not set. Admin routes will be skipped." -ForegroundColor Yellow
}
else { $AdminEmail = ($AdminEmail -split ',')[0].Trim() }

$results = New-Object System.Collections.ArrayList
$headersAdmin = @{ 'X-Admin-Email' = $AdminEmail }

function Add-Result([string]$name, [bool]$ok, $detail=$null) {
  $null = $results.Add([pscustomobject]@{ name=$name; ok=$ok; detail=$detail })
  if ($ok) { Pass $name }
  else {
    $detailStr = ''
    try { $detailStr = ($detail | ConvertTo-Json -Compress -Depth 6) } catch { try { $detailStr = ($detail | Out-String) } catch { $detailStr = '[unserializable]' } }
    Fail ("{0} -> {1}" -f $name, $detailStr)
  }
}

function Invoke-Json {
  param(
    [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')]
    [string]$Method,
    [Parameter(Mandatory)][string]$Url,
    [hashtable]$Headers,
    $Body
  )
  try {
    if ($Body -ne $null -and $Method -in @('POST','PUT','PATCH')) {
      $json = $Body | ConvertTo-Json -Depth 8 -Compress
      $resp = Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers -ContentType 'application/json' -Body $json -ErrorAction Stop
      return @{ ok=$true; body=$resp; status=200 }
    } else {
      $resp = Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers -ErrorAction Stop
      return @{ ok=$true; body=$resp; status=200 }
    }
  } catch {
    $status = $null
    $payload = $null
    try { $status = $_.Exception.Response.StatusCode.value__ } catch {}
    try {
      $stream = $_.Exception.Response.GetResponseStream(); if ($stream) { $reader = New-Object System.IO.StreamReader($stream); $payload = $reader.ReadToEnd() }
      if ($payload) { try { $payload = $payload | ConvertFrom-Json } catch {} }
    } catch {}
    return @{ ok=$false; status=$status; error=$_.Exception.Message; body=$payload }
  }
}

# Ensure at least one local PDF exists and get its id for downstream tests
function Ensure-LocalFileId {
  $lib = Invoke-Json -Method GET -Url ("{0}/api/library/list?limit=1" -f $ApiBase)
  if ($lib.ok -and $lib.body.files -and $lib.body.files.Count -gt 0) { return [string]$lib.body.files[0].id }
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
  $uploadJson = & curl.exe -s -F ("file=@{0};type=application/pdf" -f $pdfPath) ("{0}/api/files/upload" -f $ApiBase) | ConvertFrom-Json
  if ($uploadJson.id) { return [string]$uploadJson.id }
  throw "Failed to upload a sample PDF"
}

# 0) Health and diag
try {
  $r = Invoke-Json -Method GET -Url ("{0}/api/health" -f $ApiBase)
  Add-Result 'GET /api/health' ($r.ok -and $r.body.ok -eq $true) $r
} catch { Add-Result 'GET /api/health' $false $_ }
try {
  $r = Invoke-Json -Method GET -Url ("{0}/api/diag/db" -f $ApiBase)
  Add-Result 'GET /api/diag/db' ($r.ok -and $r.body.driver) $r
} catch { Add-Result 'GET /api/diag/db' $false $_ }

# 1) RBAC catalog (read-only)
try { $r = Invoke-Json -Method GET -Url ("{0}/api/rbac/permissions" -f $ApiBase); Add-Result 'GET /api/rbac/permissions' ($r.ok -and ($r.body | Measure-Object).Count -gt 0) $r } catch { Add-Result 'GET /api/rbac/permissions' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/rbac/role-permissions" -f $ApiBase); Add-Result 'GET /api/rbac/role-permissions' ($r.ok -and ($r.body | Measure-Object).Count -ge 0) $r } catch { Add-Result 'GET /api/rbac/role-permissions' $false $_ }

# 2) Modules and tenant info
try { $r = Invoke-Json -Method GET -Url ("{0}/api/modules" -f $ApiBase); Add-Result 'GET /api/modules' $r.ok $r } catch { Add-Result 'GET /api/modules' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/tenant" -f $ApiBase); Add-Result 'GET /api/tenant' ($r.ok -and $r.body.tenant) $r } catch { Add-Result 'GET /api/tenant' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/tenant/modules" -f $ApiBase); Add-Result 'GET /api/tenant/modules' $r.ok $r } catch { Add-Result 'GET /api/tenant/modules' $false $_ }

# 3) Notification emails CRUD
try {
  $emails = @{ emails = @('ops@sunbeth.local','alerts@sunbeth.local') }
  $r1 = Invoke-Json -Method POST -Url ("{0}/api/notification-emails" -f $ApiBase) -Body $emails
  $r2 = Invoke-Json -Method GET -Url ("{0}/api/notification-emails" -f $ApiBase)
  $ok = $r1.ok -and $r2.ok -and ($r2.body.emails | Where-Object { $_ -eq 'ops@sunbeth.local' }).Count -eq 1
  Add-Result 'POST/GET /api/notification-emails' $ok @{ post=$r1; get=$r2 }
} catch { Add-Result 'POST/GET /api/notification-emails' $false $_ }

# 4) Files: ensure a local file exists
[string]$fileId = ""
try { $fileId = Ensure-LocalFileId; Add-Result 'Ensure local PDF in library' ($fileId -ne "") @{ fileId=$fileId } } catch { Add-Result 'Ensure local PDF in library' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/library/list?limit=5" -f $ApiBase); Add-Result 'GET /api/library/list' $r.ok $r } catch { Add-Result 'GET /api/library/list' $false $_ }
try { if ($fileId -ne "") { $r = Invoke-Json -Method GET -Url ("{0}/api/files/{1}?diag=1" -f $ApiBase,$fileId); Add-Result 'GET /api/files/:id?diag=1' ($r.ok -and $r.body.ok -eq $true) $r } else { Add-Result 'GET /api/files/:id?diag=1' $false 'no_file_id' } } catch { Add-Result 'GET /api/files/:id?diag=1' $false $_ }

# 5) Settings: external support and legal consent
try {
  $r1 = Invoke-Json -Method GET -Url ("{0}/api/settings/external-support" -f $ApiBase)
  $r2 = Invoke-Json -Method PUT -Url ("{0}/api/settings/external-support" -f $ApiBase) -Headers $headersAdmin -Body @{ enabled = $true }
  Add-Result 'GET/PUT /api/settings/external-support' ($r1.ok -and $r2.ok -and $r2.body.enabled -eq $true) @{ get=$r1; put=$r2 }
} catch { Add-Result 'GET/PUT /api/settings/external-support' $false $_ }
try {
  $r = Invoke-Json -Method PUT -Url ("{0}/api/settings/legal-consent" -f $ApiBase) -Headers $headersAdmin -Body @{ fileId = $fileId }
  Add-Result 'PUT /api/settings/legal-consent' ($r.ok -and $r.body.fileId -eq $fileId) $r
} catch { Add-Result 'PUT /api/settings/legal-consent' $false $_ }

# 6) Admin Policies CRUD (requires SuperAdmin via header and env)
if ($AdminEmail) {
  try {
    $create = Invoke-Json -Method POST -Url ("{0}/api/admin/policies" -f $ApiBase) -Headers $headersAdmin -Body (@{ name='E2E Policy All'; description='auto'; frequency='annual'; required=$true; fileIds=@($fileId); dueInDays=30; graceDays=0; active=$true })
    $policyId = if ($create.ok) { $create.body.id } else { $null }
    $list = Invoke-Json -Method GET -Url ("{0}/api/admin/policies" -f $ApiBase) -Headers $headersAdmin
    $ok = $create.ok -and $policyId -ne $null -and $list.ok
    Add-Result 'Admin Policies: create/list' $ok @{ create=$create; list=$list }
    if ($policyId) {
      $upd = Invoke-Json -Method PUT -Url ("{0}/api/admin/policies/{1}" -f $ApiBase,$policyId) -Headers $headersAdmin -Body @{ description='updated' }
      Add-Result 'Admin Policies: update' $upd.ok $upd
      $del = Invoke-Json -Method DELETE -Url ("{0}/api/admin/policies/{1}" -f $ApiBase,$policyId) -Headers $headersAdmin
      Add-Result 'Admin Policies: delete' ($del.ok -and $del.body.ok -eq $true) $del
    }
  } catch { Add-Result 'Admin Policies (CRUD)' $false $_ }
} else {
  Info 'Skipping Admin Policies (no SuperAdmin configured)'
}

# 7) Batches flow (create full -> read -> update -> delete)
try {
  $batchBody = @{ 
    name = 'E2E Batch All'; description='auto'; status=1; 
    documents = @(@{ title='E2E Doc'; url='https://example.com/sample.pdf'; version=1; requiresSignature=$false; localFileId=$fileId; localUrl=("/api/files/{0}" -f $fileId) }) ;
    recipients = @(@{ email = 'ack.user@sunbeth.local'; displayName='Ack User' })
  }
  $create = Invoke-Json -Method POST -Url ("{0}/api/batches/full" -f $ApiBase) -Body $batchBody
  $bid = if ($create.ok) { $create.body.id } else { $null }
  Add-Result 'POST /api/batches/full' ($create.ok -and $bid) $create
  if ($bid) {
    $docs = Invoke-Json -Method GET -Url ("{0}/api/batches/{1}/documents" -f $ApiBase,$bid)
    Add-Result 'GET /api/batches/:id/documents' ($docs.ok -and $docs.body.documents.Count -ge 1) $docs
    $recs = Invoke-Json -Method GET -Url ("{0}/api/batches/{1}/recipients" -f $ApiBase,$bid)
    Add-Result 'GET /api/batches/:id/recipients' ($recs.ok -and $recs.body.recipients.Count -ge 1) $recs
    $list = Invoke-Json -Method GET -Url ("{0}/api/batches" -f $ApiBase)
    Add-Result 'GET /api/batches' $list.ok $list
    $upd = Invoke-Json -Method PUT -Url ("{0}/api/batches/{1}" -f $ApiBase,$bid) -Body @{ description='updated desc' }
    Add-Result 'PUT /api/batches/:id' $upd.ok $upd
    $del = Invoke-Json -Method DELETE -Url ("{0}/api/batches/{1}" -f $ApiBase,$bid)
    Add-Result 'DELETE /api/batches/:id' ($del.ok -and $del.body.ok -eq $true) $del
  }
} catch { Add-Result 'Batches full flow' $false $_ }

# 8) Businesses CRUD (simple)
try { $r = Invoke-Json -Method GET -Url ("{0}/api/businesses" -f $ApiBase); Add-Result 'GET /api/businesses' $r.ok $r } catch { Add-Result 'GET /api/businesses' $false $_ }
try {
  $cr = Invoke-Json -Method POST -Url ("{0}/api/businesses" -f $ApiBase) -Body @{ name='E2E Biz'; code='E2E' }
  $id = if ($cr.ok) { [int]$cr.body.id } else { 0 }
  Add-Result 'POST /api/businesses' ($cr.ok -and $id -gt 0) $cr
  if ($id -gt 0) {
    $up = Invoke-Json -Method PUT -Url ("{0}/api/businesses/{1}" -f $ApiBase,$id) -Body @{ description='updated' }
    Add-Result 'PUT /api/businesses/:id' $up.ok $up
    $dl = Invoke-Json -Method DELETE -Url ("{0}/api/businesses/{1}" -f $ApiBase,$id)
    Add-Result 'DELETE /api/businesses/:id' ($dl.ok -and $dl.body.ok -eq $true) $dl
  }
} catch { Add-Result 'Businesses CRUD' $false $_ }

# 9) Stats and reports
try { $r = Invoke-Json -Method GET -Url ("{0}/api/stats" -f $ApiBase); Add-Result 'GET /api/stats' $r.ok $r } catch { Add-Result 'GET /api/stats' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/compliance" -f $ApiBase); Add-Result 'GET /api/compliance' $r.ok $r } catch { Add-Result 'GET /api/compliance' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/doc-stats" -f $ApiBase); Add-Result 'GET /api/doc-stats' $r.ok $r } catch { Add-Result 'GET /api/doc-stats' $false $_ }
try { $r = Invoke-Json -Method GET -Url ("{0}/api/trends" -f $ApiBase); Add-Result 'GET /api/trends' $r.ok $r } catch { Add-Result 'GET /api/trends' $false $_ }

# 10) Receipts & consents (happy path)
try {
  $email = "consent.user@sunbeth.local"
  $c = Invoke-Json -Method POST -Url ("{0}/api/consents" -f $ApiBase) -Body @{ email = $email }
  Add-Result 'POST /api/consents' $c.ok $c
} catch { Add-Result 'POST /api/consents' $false $_ }

# 11) Admin settings (whitelist)
if ($AdminEmail) {
  try {
    $put = Invoke-Json -Method PUT -Url ("{0}/api/admin/settings" -f $ApiBase) -Body @{ settings = @{ allowed_origins = 'http://localhost:3000' } } -Headers $headersAdmin
    Add-Result 'PUT /api/admin/settings' $put.ok $put
    $get = Invoke-Json -Method GET -Url ("{0}/api/admin/settings" -f $ApiBase)
    Add-Result 'GET /api/admin/settings' ($get.ok -and $get.body.settings) $get
  } catch { Add-Result 'Admin settings' $false $_ }
} else { Info 'Skipping Admin settings (no SuperAdmin configured)' }

# 12) Optional: Proxy checks (skipped unless -IncludeNetwork is set)
if ($IncludeNetwork) {
  try { $r = Invoke-Json -Method GET -Url ("{0}/api/proxy?url=https://example.com" -f $ApiBase); Add-Result 'GET /api/proxy?url=example.com' $r.ok $r } catch { Add-Result 'GET /api/proxy' $false $_ }
}

# Summary
$passed = ($results | Where-Object { $_.ok }).Count
$total = $results.Count
$failed = $total - $passed
Write-Host ("`n=================================")
$fg = 'Green'
if ($failed -gt 0) { $fg = 'Yellow' }
Write-Host ("E2E SUMMARY: {0}/{1} passed, {2} failed" -f $passed, $total, $failed) -ForegroundColor $fg
if ($failed -gt 0) { exit 2 } else { exit 0 }
