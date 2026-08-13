# Regression test for the collection/bare-object paging contract in RestClient.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$script:SocScriptVersion = 'test'
foreach ($f in 'Common.ps1','Auth.ps1','RestClient.ps1') { . (Join-Path $root 'private' $f) }

$script:SocAuth = [pscustomobject]@{ Environment='Global'; Tokens=@{} }
function Get-SocToken { param($Resource) 'tok' }

$fail = 0
function Check($label, $expected, $actual) {
    if ($expected -eq $actual) { Write-Host "  PASS  $label (= $actual)" -ForegroundColor Green }
    else { Write-Host "  FAIL  $label — expected $expected, got $actual" -ForegroundColor Red; $script:fail++ }
}

$script:responses = @{}
function Invoke-RestMethod {
    [CmdletBinding()]
    param([string]$Method='GET', [string]$Uri, $Headers, $Body)
    foreach ($k in $script:responses.Keys) { if ($Uri -like "*$k*") { return $script:responses[$k] } }
    throw "no fixture for $Uri"
}

Write-Host "`nPaging contract" -ForegroundColor Cyan

# 1. populated collection
$script:responses = @{ '/a' = [pscustomobject]@{ value = @([pscustomobject]@{id=1}, [pscustomobject]@{id=2}) } }
Check 'populated collection -> 2 items' 2 @(Invoke-SocGraphRequest -Path '/a').Count

# 2. empty collection — the regression
$script:responses = @{ '/b' = [pscustomobject]@{ value = @() } }
$empty = @(Invoke-SocGraphRequest -Path '/b')
Check 'empty collection -> 0 items' 0 $empty.Count

# 3. bare single object (no value property)
$script:responses = @{ '/c' = [pscustomobject]@{ id='x'; isEnabled=$false } }
$bare = @(Invoke-SocGraphRequest -Path '/c')
Check 'bare object -> 1 item' 1 $bare.Count
Check 'bare object preserved (not an envelope)' 'x' $bare[0].id

# 4. multi-page follows nextLink
# NOTE: -like treats '?' as a single-char wildcard, so fixture keys must not
# contain one, or page 2 re-matches page 1 and the follow loop never ends.
$script:responses = [ordered]@{
  '/pagetwo' = [pscustomobject]@{ value=@([pscustomobject]@{id=2},[pscustomobject]@{id=3}) }
  '/pageone' = [pscustomobject]@{ value=@([pscustomobject]@{id=1}); '@odata.nextLink'='https://graph.microsoft.com/v1.0/pagetwo' }
}
Check 'paged collection -> 3 items' 3 @(Invoke-SocGraphRequest -Path '/pageone').Count

# 4b. self-referential nextLink must terminate, not hang
$script:SocMaxPages = 5
$script:responses = [ordered]@{
  '/loop' = [pscustomobject]@{ value=@([pscustomobject]@{id=1}); '@odata.nextLink'='https://graph.microsoft.com/v1.0/loop' }
}
Check 'self-referential nextLink is capped' 5 @(Invoke-SocGraphRequest -Path '/loop' 3>$null).Count
$script:SocMaxPages = 1000

# 5. ARM empty collection
$script:responses = @{ '/e' = [pscustomobject]@{ value = @() } }
Check 'ARM empty collection -> 0 items' 0 @(Invoke-SocArmRequest -Path '/e' -ApiVersion '2024-01-01').Count

# 6. Defender empty collection
$script:responses = @{ '/f' = [pscustomobject]@{ value = @() } }
Check 'Defender empty collection -> 0 items' 0 @(Invoke-SocDefenderRequest -Path '/f').Count

Write-Host ""
if ($fail -gt 0) { Write-Host "$fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "All paging assertions passed." -ForegroundColor Green
