#Requires -Version 7.0

<#
.SYNOPSIS
    Creates the app registration used by Export-SocTenantSettings.ps1.

.DESCRIPTION
    Provisions everything the export needs in one pass: the app registration and
    service principal, the Microsoft Graph application permissions, the
    Exchange.ManageAsApp permission that the Exchange/Purview collectors depend
    on, the Defender for Endpoint scopes, admin consent, a certificate, the
    directory role assignment, and Azure RBAC.

    Permission IDs are resolved from each resource service principal at run time
    rather than hardcoded, so this does not rot when Microsoft adds or renames
    scopes, and a rename fails loudly instead of silently granting a wrong GUID.

    On Windows the certificate is created with a CSP key provider, because
    Exchange Online app-only authentication rejects CNG certificates — which is
    what New-SelfSignedCertificate produces by default. Elsewhere it falls back
    to openssl.

    Drives the Azure CLI, so `az` must be installed and signed in. Requires an
    account that can create app registrations and grant admin consent: Global
    Administrator, or Application Administrator plus Privileged Role
    Administrator.

.PARAMETER AppName
    Display name for the app registration. An existing app with this name is
    reused rather than duplicated.

.PARAMETER Sections
    All   — every permission, including Exchange/Purview, Defender and Azure.
    Entra — only the identity scopes needed for -Include Entra,Applications.
            Nothing for Exchange, Purview, Intune, Governance or the Defender
            API is requested or consented to.

.PARAMETER SubscriptionId
    Subscriptions to assign Reader and Security Reader on, for the Azure and
    Sentinel sections. Omit to skip Azure RBAC entirely.

.PARAMETER DirectoryRole
    Directory role assigned to the service principal. Required for the Exchange,
    Defender for Office 365 and Purview sections. Global Reader covers all three
    read-only.

.PARAMETER CertificateDirectory
    Where the generated certificate and key are written.

.PARAMETER CertificateYears
    Certificate lifetime. Defaults to 2.

.PARAMETER SkipCertificate
    Do not create or upload a certificate. Use when attaching your own.

.EXAMPLE
    ./New-SocAppRegistration.ps1 -SubscriptionId 00000000-1111-2222-3333-444444444444

    Everything, including Azure RBAC on one subscription.

.EXAMPLE
    ./New-SocAppRegistration.ps1 -Sections Entra

    Identity configuration only — no Exchange, Purview, Defender or Azure scopes.

.EXAMPLE
    ./New-SocAppRegistration.ps1 -WhatIf

    Show what would be created and granted without changing anything.

.NOTES
    A bash equivalent for Azure Cloud Shell lives alongside this file as
    new-soc-app-registration.sh.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AppName = 'SOC Tenant Settings Export',

    [ValidateSet('All', 'Entra')]
    [string]$Sections = 'All',

    [string[]]$SubscriptionId,

    [string]$DirectoryRole = 'Global Reader',

    [string]$CertificateDirectory = (Join-Path (Get-Location).Path 'soc-export-cert'),

    [ValidateRange(1, 10)]
    [int]$CertificateYears = 2,

    [switch]$SkipCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Well-known first-party resource app IDs.
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$ExoAppId = '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online
$MdeAppId = 'fc780465-2017-40d4-a0c5-307022471b92'   # WindowsDefenderATP

$GraphPermissionsCore = @(
    'Organization.Read.All', 'Directory.Read.All', 'Domain.Read.All'
    'Policy.Read.All', 'Policy.Read.AuthenticationMethod', 'Policy.Read.PermissionGrant'
    'RoleManagement.Read.Directory', 'AdministrativeUnit.Read.All'
    'Application.Read.All', 'AuditLog.Read.All', 'User.Read.All', 'Device.Read.All'
    'IdentityRiskyUser.Read.All', 'IdentityRiskyServicePrincipal.Read.All'
)

$GraphPermissionsFull = @(
    'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.Read.All'
    'DeviceManagementServiceConfig.Read.All', 'DeviceManagementManagedDevices.Read.All'
    'AccessReview.Read.All', 'EntitlementManagement.Read.All', 'Agreement.Read.All'
    'PrivilegedAccess.Read.AzureADGroup'
    'SecurityEvents.Read.All', 'SecurityAlert.Read.All', 'CustomDetection.Read.All'
)

# Ti.ReadWrite.All is the only permission the List Indicators API accepts —
# Microsoft publishes no read-only variant. Removing it costs only the
# defender-indicators artifact.
$MdePermissions = @('Score.Read.All', 'SecurityRecommendation.Read.All', 'Ti.ReadWrite.All')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host " ok $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host " !  $Message" -ForegroundColor Yellow }

function Invoke-Az {
    <#
        .SYNOPSIS
            Runs the Azure CLI, returning parsed JSON or $null on failure.

        .DESCRIPTION
            az reports failure through the exit code rather than by throwing, so
            every call is checked. -AllowFailure converts an expected failure
            (an assignment that already exists, a resource absent from this
            tenant) into $null instead of a terminating error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowFailure,
        [switch]$Raw
    )

    $stdout = & az @Arguments 2>$null
    $exit = $LASTEXITCODE

    if ($exit -ne 0) {
        if ($AllowFailure) { return $null }
        throw "az $($Arguments -join ' ') failed with exit code $exit."
    }

    if ($Raw -or -not $stdout) { return $stdout }

    $text = ($stdout | Out-String).Trim()
    if (-not $text) { return $null }

    try { return $text | ConvertFrom-Json }
    catch { return $text }
}

function Get-AppRoleId {
    <#
        .SYNOPSIS
            Resolves an application permission name to its appRole GUID on a
            resource service principal.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceAppId, [Parameter(Mandatory)][string]$Permission)

    $query = "appRoles[?value=='$Permission' && contains(allowedMemberTypes,'Application')].id | [0]"
    $id = Invoke-Az -AllowFailure -Raw -Arguments @(
        'ad', 'sp', 'show', '--id', $ResourceAppId, '--query', $query, '-o', 'tsv')

    $value = ($id | Out-String).Trim()
    if (-not $value -or $value -eq 'None') { return $null }
    return $value
}

function Assert-ResourceServicePrincipal {
    <#
        .SYNOPSIS
            Ensures a resource service principal exists so its appRoles can be
            enumerated. Returns $false when the resource is not available in
            this tenant.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceAppId)

    if (Invoke-Az -AllowFailure -Arguments @('ad', 'sp', 'show', '--id', $ResourceAppId)) { return $true }
    if (Invoke-Az -AllowFailure -Arguments @('ad', 'sp', 'create', '--id', $ResourceAppId)) { return $true }
    return $false
}

function Add-AppPermission {
    <#
        .SYNOPSIS
            Adds a resource's application permissions in one call.

        .DESCRIPTION
            az rewrites requiredResourceAccess wholesale, so adding permissions
            one at a time is both slower and racier than a single call.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$ResourceAppId,
        [Parameter(Mandatory)][string[]]$Permissions,
        [Parameter(Mandatory)][string]$ResourceLabel
    )

    $resolved = [System.Collections.Generic.List[string]]::new()
    foreach ($permission in $Permissions) {
        $roleId = Get-AppRoleId -ResourceAppId $ResourceAppId -Permission $permission
        if ($roleId) { $resolved.Add("$roleId=Role") }
        else { Write-Warn "$ResourceLabel permission not found, skipping: $permission" }
    }

    if ($resolved.Count -eq 0) { return 0 }

    if ($PSCmdlet.ShouldProcess($AppId, "Add $($resolved.Count) $ResourceLabel application permission(s)")) {
        Invoke-Az -Arguments (@(
                'ad', 'app', 'permission', 'add', '--id', $AppId,
                '--api', $ResourceAppId, '--only-show-errors', '--api-permissions') + $resolved) | Out-Null
    }

    return $resolved.Count
}

function New-SocCertificate {
    <#
        .SYNOPSIS
            Creates the authentication certificate.

        .DESCRIPTION
            On Windows the CSP provider is specified explicitly: Exchange Online
            app-only authentication rejects CNG certificates, and CNG is what
            New-SelfSignedCertificate produces by default. Other platforms use
            openssl, whose output is CSP-compatible.

        .OUTPUTS
            An object with PemPath, PfxPath and Thumbprint.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][int]$Years)

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }

    $pemPath = Join-Path $Directory 'soc-export.pem'
    $pfxPath = Join-Path $Directory 'soc-export.pfx'

    if ($IsWindows) {
        $certificate = New-SelfSignedCertificate -Subject "CN=$Subject" `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 `
            -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($Years) `
            -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'

        # az expects PEM; Export-Certificate writes DER.
        $encoded = [Convert]::ToBase64String(
            $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert),
            [Base64FormattingOptions]::InsertLineBreaks)
        Set-Content -LiteralPath $pemPath -Encoding ascii -Value @"
-----BEGIN CERTIFICATE-----
$encoded
-----END CERTIFICATE-----
"@

        Export-PfxCertificate -Cert $certificate -FilePath $pfxPath `
            -Password (ConvertTo-SecureString -String ([guid]::NewGuid()) -AsPlainText -Force) | Out-Null

        return [pscustomobject]@{
            PemPath    = $pemPath
            PfxPath    = $pfxPath
            Thumbprint = $certificate.Thumbprint
            InStore    = $true
        }
    }

    if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
        throw 'openssl is required to generate a certificate on this platform. Use -SkipCertificate and supply your own.'
    }

    $keyPath = Join-Path $Directory 'soc-export.key'
    & openssl req -x509 -newkey rsa:2048 -sha256 -days ($Years * 365) -nodes `
        -keyout $keyPath -out $pemPath -subj "/CN=$Subject" 2>$null
    & openssl pkcs12 -export -out $pfxPath -inkey $keyPath -in $pemPath -passout 'pass:' 2>$null

    $thumbprint = (& openssl x509 -in $pemPath -noout -fingerprint -sha1) -replace '.*=', '' -replace ':', ''

    return [pscustomobject]@{
        PemPath    = $pemPath
        PfxPath    = $pfxPath
        Thumbprint = $thumbprint.Trim()
        InStore    = $false
    }
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'The Azure CLI (az) is not installed or not on PATH. See https://learn.microsoft.com/cli/azure/install-azure-cli'
}

$account = Invoke-Az -AllowFailure -Arguments @('account', 'show')
if (-not $account) {
    throw 'Not signed in to the Azure CLI. Run: az login --allow-no-subscriptions'
}

$tenantId = $account.tenantId
Write-Step "Tenant: $tenantId"

# ---------------------------------------------------------------------------
# App registration and service principal
# ---------------------------------------------------------------------------

$existing = Invoke-Az -AllowFailure -Raw -Arguments @(
    'ad', 'app', 'list', '--display-name', $AppName, '--query', '[0].appId', '-o', 'tsv')
$appId = ($existing | Out-String).Trim()

if ($appId -and $appId -ne 'None') {
    Write-Warn "Reusing existing app registration '$AppName' ($appId)"
}
elseif ($PSCmdlet.ShouldProcess($AppName, 'Create app registration')) {
    Write-Step "Creating app registration '$AppName'"
    $created = Invoke-Az -Arguments @(
        'ad', 'app', 'create', '--display-name', $AppName, '--sign-in-audience', 'AzureADMyOrg')
    $appId = $created.appId
}
else {
    $appId = '<app-id>'
}

$servicePrincipalObjectId = $null
if ($appId -ne '<app-id>') {
    if (-not (Invoke-Az -AllowFailure -Arguments @('ad', 'sp', 'show', '--id', $appId))) {
        if ($PSCmdlet.ShouldProcess($appId, 'Create service principal')) {
            Invoke-Az -Arguments @('ad', 'sp', 'create', '--id', $appId) | Out-Null
        }
    }
    $servicePrincipalObjectId = ($(Invoke-Az -AllowFailure -Raw -Arguments @(
                'ad', 'sp', 'show', '--id', $appId, '--query', 'id', '-o', 'tsv')) | Out-String).Trim()
    Write-Ok "Service principal object ID: $servicePrincipalObjectId"
}

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

$graphPermissions = if ($Sections -eq 'All') { $GraphPermissionsCore + $GraphPermissionsFull } else { $GraphPermissionsCore }

if (-not (Assert-ResourceServicePrincipal -ResourceAppId $GraphAppId)) {
    throw 'The Microsoft Graph service principal is unavailable in this tenant.'
}

Write-Step "Resolving $($graphPermissions.Count) Microsoft Graph permissions"
$granted = Add-AppPermission -AppId $appId -ResourceAppId $GraphAppId `
    -Permissions $graphPermissions -ResourceLabel 'Graph'
Write-Ok "$granted Graph permission(s) requested"

if ($Sections -eq 'All') {
    # Without Exchange.ManageAsApp the Exchange, Defender for Office 365 and
    # Purview collectors (60 artifacts) cannot connect at all.
    if (Assert-ResourceServicePrincipal -ResourceAppId $ExoAppId) {
        Write-Step 'Adding Exchange.ManageAsApp'
        $exoGranted = Add-AppPermission -AppId $appId -ResourceAppId $ExoAppId `
            -Permissions @('Exchange.ManageAsApp') -ResourceLabel 'Exchange Online'
        if ($exoGranted -eq 0) {
            Write-Warn 'Exchange.ManageAsApp unavailable — Exchange/DefenderOffice/Purview sections will be skipped.'
        }
    }
    else {
        Write-Warn 'Office 365 Exchange Online not available in this tenant.'
    }

    if (Assert-ResourceServicePrincipal -ResourceAppId $MdeAppId) {
        Write-Step 'Adding Defender for Endpoint permissions'
        Add-AppPermission -AppId $appId -ResourceAppId $MdeAppId `
            -Permissions $MdePermissions -ResourceLabel 'Defender for Endpoint' | Out-Null
    }
    else {
        Write-Warn 'WindowsDefenderATP not present — Defender API artifacts will be skipped.'
    }
}

# ---------------------------------------------------------------------------
# Admin consent
# ---------------------------------------------------------------------------

if ($PSCmdlet.ShouldProcess($appId, 'Grant admin consent')) {
    Write-Step 'Granting admin consent (needs Global Administrator or Privileged Role Administrator)'
    # Consent against a just-created app frequently 404s until it replicates.
    Start-Sleep -Seconds 10
    if (-not (Invoke-Az -AllowFailure -Arguments @('ad', 'app', 'permission', 'admin-consent', '--id', $appId))) {
        Write-Warn "Admin consent failed. Grant it in the portal: Entra ID > App registrations > $AppName > API permissions"
    }
    else {
        Write-Ok 'Admin consent granted'
    }
}

# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------

$certificate = $null
if (-not $SkipCertificate -and $PSCmdlet.ShouldProcess($AppName, 'Create and upload certificate')) {
    Write-Step "Generating certificate (valid $CertificateYears year(s))"
    $certificate = New-SocCertificate -Directory $CertificateDirectory -Subject $AppName -Years $CertificateYears

    Invoke-Az -Arguments @(
        'ad', 'app', 'credential', 'reset', '--id', $appId,
        '--cert', "@$($certificate.PemPath)", '--append',
        '--years', "$CertificateYears", '--only-show-errors') | Out-Null

    Write-Ok "Certificate uploaded (thumbprint $($certificate.Thumbprint))"
}

# ---------------------------------------------------------------------------
# Directory role
# ---------------------------------------------------------------------------

if ($Sections -eq 'All' -and $servicePrincipalObjectId -and
    $PSCmdlet.ShouldProcess($DirectoryRole, 'Assign directory role to the service principal')) {

    Write-Step "Assigning directory role '$DirectoryRole'"
    $roleQuery = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$DirectoryRole'"
    $roleDefinitionId = ($(Invoke-Az -AllowFailure -Raw -Arguments @(
                'rest', '--method', 'GET', '--url', $roleQuery, '--query', 'value[0].id', '-o', 'tsv')) | Out-String).Trim()

    if ($roleDefinitionId -and $roleDefinitionId -ne 'None') {
        $body = @{
            '@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
            roleDefinitionId = $roleDefinitionId
            principalId      = $servicePrincipalObjectId
            directoryScopeId = '/'
        } | ConvertTo-Json -Compress

        $assigned = Invoke-Az -AllowFailure -Arguments @(
            'rest', '--method', 'POST',
            '--url', 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments',
            '--headers', 'Content-Type=application/json', '--body', $body)

        if ($assigned) { Write-Ok "Directory role '$DirectoryRole' assigned" }
        else { Write-Warn 'Directory role assignment failed (it may already exist, or you lack Privileged Role Administrator).' }
    }
    else {
        Write-Warn "Directory role '$DirectoryRole' not found."
    }
}

# ---------------------------------------------------------------------------
# Azure RBAC
# ---------------------------------------------------------------------------

if ($SubscriptionId -and $servicePrincipalObjectId) {
    foreach ($subscription in $SubscriptionId) {
        Write-Step "Assigning Azure roles on subscription $subscription"
        foreach ($role in 'Reader', 'Security Reader') {
            if (-not $PSCmdlet.ShouldProcess("$subscription", "Assign '$role'")) { continue }

            $result = Invoke-Az -AllowFailure -Arguments @(
                'role', 'assignment', 'create',
                '--assignee-object-id', $servicePrincipalObjectId,
                '--assignee-principal-type', 'ServicePrincipal',
                '--role', $role, '--scope', "/subscriptions/$subscription", '--only-show-errors')

            if ($result) { Write-Ok "  $role" } else { Write-Warn "  $role assignment failed (may already exist)" }
        }
    }
}
else {
    Write-Warn 'No -SubscriptionId supplied — Azure and Sentinel sections will be skipped.'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

$primaryDomain = ($(Invoke-Az -AllowFailure -Raw -Arguments @(
            'rest', '--method', 'GET', '--url', 'https://graph.microsoft.com/v1.0/domains',
            '--query', 'value[?isInitial].id | [0]', '-o', 'tsv')) | Out-String).Trim()
if (-not $primaryDomain -or $primaryDomain -eq 'None') { $primaryDomain = $tenantId }

Write-Host ''
Write-Host 'App registration ready.' -ForegroundColor Green
Write-Host ''
Write-Host "  Application (client) ID : $appId"
Write-Host "  Service principal       : $servicePrincipalObjectId"
Write-Host "  Tenant                  : $primaryDomain ($tenantId)"

if ($certificate) {
    Write-Host "  Certificate             : $($certificate.PfxPath)"
    Write-Host "  Thumbprint              : $($certificate.Thumbprint)"
}

Write-Host ''
Write-Host 'Verify the grant before the first real run:' -ForegroundColor Cyan
Write-Host '  ./Export-SocTenantSettings.ps1 -ListArtifacts | Format-Table Section,Name,Permission'
Write-Host ''
Write-Host 'Then run the export:' -ForegroundColor Cyan

if ($certificate -and $certificate.InStore) {
    Write-Host "  ./Export-SocTenantSettings.ps1 -TenantId $primaryDomain ``"
    Write-Host "      -AuthMode Certificate -ClientId $appId ``"
    Write-Host "      -CertificateThumbprint $($certificate.Thumbprint)"
}
elseif ($certificate) {
    Write-Host "  ./Export-SocTenantSettings.ps1 -TenantId $primaryDomain ``"
    Write-Host "      -AuthMode Certificate -ClientId $appId ``"
    Write-Host "      -CertificatePath $($certificate.PfxPath)"
}

Write-Host ''
Write-Host 'Still to do by hand:' -ForegroundColor Yellow
Write-Host '  * Microsoft Sentinel Reader on any Sentinel workspace you want collected.'
Write-Host '  * Reader at tenant root for the entra-diagnostic-settings artifact (a Global'
Write-Host '    Administrator must first elevate access under Entra ID > Properties >'
Write-Host '    Access management for Azure resources).'
