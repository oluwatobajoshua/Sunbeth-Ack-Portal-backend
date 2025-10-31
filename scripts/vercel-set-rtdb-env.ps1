param(
  [Parameter(Mandatory=$true)][string]$Project,                 # e.g. sunbeth-ack-portal-backend-spny
  [Parameter(Mandatory=$false)][string]$Scope,                  # optional Vercel org scope (team slug)
  [Parameter(Mandatory=$true)][string]$FirebaseProjectId,       # e.g. sunbeth-ack-portal
  [Parameter(Mandatory=$true)][string]$FirebaseDatabaseUrl,     # e.g. https://<project>-default-rtdb.firebaseio.com/
  [Parameter(Mandatory=$true)][string]$ServiceAccountPath,      # path to serviceAccount.json
  [Parameter(Mandatory=$false)][string]$SuperAdmins,            # comma-separated emails
  [Parameter(Mandatory=$false)][string]$AllowedOrigins          # optional: comma-separated allowed CORS origins
)

# This script sets Production env vars on a Vercel project for Firebase RTDB and triggers a prod deploy.
# Requirements: Vercel CLI logged in and access to the target project.
# Usage example:
#   ./scripts/vercel-set-rtdb-env.ps1 -Project "sunbeth-ack-portal-backend-spny" \ 
#     -FirebaseProjectId "sunbeth-ack-portal" \ 
#     -FirebaseDatabaseUrl "https://sunbeth-ack-portal-default-rtdb.firebaseio.com/" \ 
#     -ServiceAccountPath "c:\\path\\to\\serviceAccount.json" \ 
#     -SuperAdmins "oluwatoba.ogunsakinr@sunbeth.net"

$ErrorActionPreference = 'Stop'

function Add-Env([string]$Name, [string]$Value) {
  Write-Host "Setting $Name (production)" -ForegroundColor Cyan
  $args = "env add `"$Name`" production"
  if ($Scope) { $args = $args + " --scope `"$Scope`"" }

  $pinfo = New-Object System.Diagnostics.ProcessStartInfo
  # Use cmd.exe to ensure Windows can resolve vercel.cmd on PATH
  $pinfo.FileName = 'cmd.exe'
  $pinfo.Arguments = "/c vercel $args"
  $pinfo.RedirectStandardInput = $true
  $pinfo.RedirectStandardOutput = $true
  $pinfo.RedirectStandardError = $true
  $pinfo.UseShellExecute = $false
  if ($script:RepoRoot) { $pinfo.WorkingDirectory = $script:RepoRoot }

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $pinfo
  if (-not $p.Start()) { throw "Failed to start vercel env add for $Name" }
  # Feed value via stdin and close
  $p.StandardInput.Write($Value)
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) {
    if ($out) { Write-Host $out -ForegroundColor DarkGray }
    if ($err) { Write-Host $err -ForegroundColor Red }
    # If variable already exists, try to remove and re-add
    if (($out -match 'already exists') -or ($err -match 'already exists')) {
      Write-Host "Variable $Name already exists. Attempting to remove and re-add..." -ForegroundColor Yellow
      Remove-Env -Name $Name
      return Add-Env -Name $Name -Value $Value
    }
    if (($out -match 'already been added to all Environments') -or ($err -match 'already been added to all Environments')) {
      Write-Host "Variable $Name exists in All Environments. Removing globally and re-adding..." -ForegroundColor Yellow
      Remove-Env -Name $Name -All
      return Add-Env -Name $Name -Value $Value
    }
    throw "vercel env add failed for $Name (exit $($p.ExitCode))"
  }
  if ($out) { Write-Host $out -ForegroundColor Green }
}

function Remove-Env([string]$Name, [switch]$All) {
  Write-Host "Removing $Name (production)" -ForegroundColor DarkYellow
  $args = if ($All) { "env rm `"$Name`" -y" } else { "env rm `"$Name`" production -y" }
  if ($Scope) { $args = $args + " --scope `"$Scope`"" }

  $pinfo = New-Object System.Diagnostics.ProcessStartInfo
  $pinfo.FileName = 'cmd.exe'
  $pinfo.Arguments = "/c vercel $args"
  $pinfo.RedirectStandardOutput = $true
  $pinfo.RedirectStandardError = $true
  $pinfo.UseShellExecute = $false
  if ($script:RepoRoot) { $pinfo.WorkingDirectory = $script:RepoRoot }

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $pinfo
  if (-not $p.Start()) { throw "Failed to start vercel env rm for $Name" }
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) {
    if ($out) { Write-Host $out -ForegroundColor DarkGray }
    if ($err) { Write-Host $err -ForegroundColor Red }
    throw "vercel env rm failed for $Name (exit $($p.ExitCode))"
  }
  if ($out) { Write-Host $out -ForegroundColor DarkGray }
}

# 0) Sanity checks
vercel --version | Out-Null
# Ensure we are in backend folder and linked to target project
try {
  Set-Location (Split-Path $PSScriptRoot -Parent)
} catch {}
$script:RepoRoot = (Get-Location).Path
$linkCmd = "vercel link --yes --project `"$Project`"" + ($(if($Scope){" --scope `"$Scope`""} else {''}))
Write-Host "Linking to project '$Project'..." -ForegroundColor Cyan
& cmd.exe /c $linkCmd
if (-not (Test-Path -LiteralPath $ServiceAccountPath)) { throw "Service account file not found: $ServiceAccountPath" }

# 1) Compute base64 of service account JSON (safer for CLI input)
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ServiceAccountPath))

# 2) Set required variables
Add-Env -Name 'DB_DRIVER' -Value 'rtdb'
Add-Env -Name 'FIREBASE_PROJECT_ID' -Value $FirebaseProjectId
Add-Env -Name 'FIREBASE_DATABASE_URL' -Value $FirebaseDatabaseUrl
Add-Env -Name 'FIREBASE_SERVICE_ACCOUNT_JSON' -Value $b64

# 3) Optional: super admins for admin UI convenience
if ($SuperAdmins) {
  Add-Env -Name 'REACT_APP_SUPER_ADMINS' -Value $SuperAdmins
}

# 3b) Optional: strict CORS allow-list for frontend
if ($AllowedOrigins) {
  Add-Env -Name 'ALLOWED_ORIGINS' -Value $AllowedOrigins
}

# 4) Show current env
$envCmd = "vercel env ls" + ($(if($Scope){" --scope `"$Scope`""} else {''}))
& cmd.exe /c $envCmd | Select-String -Pattern 'production' | ForEach-Object { $_.Line }

# 5) Deploy
Write-Host "Triggering Production deploy..." -ForegroundColor Cyan
$deployCmd = "vercel deploy --prod --yes" + ($(if($Scope){" --scope `"$Scope`""} else {''}))
& cmd.exe /c $deployCmd
Write-Host "Done." -ForegroundColor Green
