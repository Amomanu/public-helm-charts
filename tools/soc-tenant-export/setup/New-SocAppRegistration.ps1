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

.PARAMETER TenantId
    The tenant to provision in, as a GUID or a verified domain. Required.

    This is checked against the tenant the Azure CLI is actually signed in to,
    and the script stops if they differ. Everything here is directory-scoped and
    consequential — an app registration, admin consent, a directory role — so it
    refuses to act on whichever tenant a stale `az login` happens to point at.

.PARAMETER AppName
    Display name for the app registration. An existing app with this name is
    reused rather than duplicated.

.PARAMETER Sections
    All   — every permission, including Exchange/Purview, Defender and Azure.
    Entra — only the identity scopes needed for -Include Entra,Applications.
            Nothing for Exchange, Purview, Intune, Governance or the Defender
            API is requested or consented to.

.PARAMETER TenantRootScope
    Also grant the Azure RBAC needed by the Azure and Sentinel sections, once, at
    the tenant root management group.

    Azure RBAC is a separate permission system from Microsoft Entra. Graph
    application permissions are tenant-wide and cover the identity sections
    outright, but they grant nothing over Azure resources: Defender for Cloud,
    Sentinel, Log Analytics and diagnostic settings all live inside
    subscriptions and are governed by Azure role assignments.

    The tenant root management group has the same ID as the tenant, and every
    subscription in the directory inherits from it — including subscriptions
    created later. That makes one assignment here the tenant-shaped answer, and
    it is what Defender for Cloud itself recommends for tenant-wide visibility.

    The cost is that nobody has access to the root management group by default:
    a Global Administrator must first elevate access under Entra ID >
    Properties > Access management for Azure resources. An assignment at this
    scope applies to every resource in the directory, so it is opt-in rather
    than default. Without it the Azure and Sentinel sections report as skipped,
    and the summary prints the command to grant it later.

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
    ./New-SocAppRegistration.ps1 -TenantId contoso.onmicrosoft.com

    Directory permissions only. The Azure and Sentinel sections are left
    unprovisioned; the summary prints how to grant them later.

.EXAMPLE
    ./New-SocAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -TenantRootScope

    Everything, including Azure RBAC covering every subscription in the tenant.

.EXAMPLE
    ./New-SocAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -Sections Entra

    Identity configuration only — no Exchange, Purview, Defender or Azure scopes.

.EXAMPLE
    ./New-SocAppRegistration.ps1 -TenantId contoso.onmicrosoft.com -WhatIf

    Show what would be created and granted without changing anything.

.NOTES
    A bash equivalent for Azure Cloud Shell lives alongside this file as
    new-soc-app-registration.sh.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [string]$AppName = 'SOC Tenant Settings Export',

    [ValidateSet('All', 'Entra')]
    [string]$Sections = 'All',

    [switch]$TenantRootScope,

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

function Stop-WithGuidance {
    <#
        .SYNOPSIS
            Prints multi-line troubleshooting text, then throws a one-line error.

        .DESCRIPTION
            PowerShell's exception renderer collapses a multi-line throw onto a
            single line, which is precisely where a wall of guidance becomes
            unreadable. Printing it first keeps the formatting; the short throw
            still terminates and still gives a non-zero exit code.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Summary, [Parameter(Mandatory)][string]$Guidance)

    Write-Host ''
    Write-Host $Summary -ForegroundColor Red
    Write-Host ''
    Write-Host $Guidance.TrimEnd()
    Write-Host ''
    throw $Summary
}

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

    # Capture stderr to a file rather than discarding it. az reports the actual
    # reason for a failure there, and throwing only the exit code makes every
    # failure undiagnosable. A file (not 2>&1) keeps az's routine stderr
    # warnings out of the success-path output, and out of PowerShell's error
    # stream where they could trip $ErrorActionPreference.
    $stderrPath = [IO.Path]::GetTempFileName()
    try {
        $stdout = & az @Arguments 2>$stderrPath
        $exit = $LASTEXITCODE
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue)
        }
        else { '' }
    }
    finally {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    if ($exit -ne 0) {
        if ($AllowFailure) { return $null }

        $detail = if ($stderr -and $stderr.Trim()) { "`n`n$($stderr.Trim())" } else { ' (az produced no error output)' }
        throw "az $($Arguments -join ' ') failed with exit code $exit.$detail"
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

# Azure CLI 2.37.0 moved the `az ad` commands from Azure AD Graph to Microsoft
# Graph, which is where --sign-in-audience and the current permission arguments
# come from. On anything older those arguments are simply unrecognised and every
# az ad call here fails with a bare exit code.
$versionInfo = Invoke-Az -AllowFailure -Arguments @('version')
if ($versionInfo -and $versionInfo.PSObject.Properties['azure-cli']) {
    $rawVersion = [string]$versionInfo.'azure-cli'
    $parsed = $null
    if ([version]::TryParse(($rawVersion -replace '[^0-9.].*$', ''), [ref]$parsed)) {
        if ($parsed -lt [version]'2.37.0') {
            Stop-WithGuidance -Summary "Azure CLI $rawVersion is too old (2.37.0 or later is required)." -Guidance @"
The 'az ad' commands moved to Microsoft Graph in Azure CLI 2.37.0, which is
where --sign-in-audience and the permission arguments used here come from.
Older versions reject them and fail with only an exit code.

Upgrade and run this again:

  az upgrade
"@
        }
    }
}

$account = Invoke-Az -AllowFailure -Arguments @('account', 'show')
if (-not $account) {
    throw "Not signed in to the Azure CLI. Run: az login --tenant $TenantId --allow-no-subscriptions"
}

$signedInTenantId = $account.tenantId

# The tenant's initial domain, so -TenantId can be given either way.
$signedInDomain = ($(Invoke-Az -AllowFailure -Raw -Arguments @(
            'rest', '--method', 'GET', '--url', 'https://graph.microsoft.com/v1.0/domains',
            '--query', 'value[?isInitial].id | [0]', '-o', 'tsv')) | Out-String).Trim()
if ($signedInDomain -eq 'None') { $signedInDomain = '' }

# Everything this script does is directory-scoped and hard to walk back — an app
# registration, admin consent, a directory role. Confirm the signed-in tenant is
# the one that was asked for rather than whichever tenant a stale az login points
# at, which is how an MSP provisions into the wrong customer.
$requested = $TenantId.Trim()
$tenantMatches = $requested -eq $signedInTenantId -or
    ($signedInDomain -and $requested -eq $signedInDomain)

if (-not $tenantMatches) {
    $actual = if ($signedInDomain) { "$signedInTenantId ($signedInDomain)" } else { $signedInTenantId }
    Stop-WithGuidance -Summary 'Refusing to act: the Azure CLI is signed in to a different tenant.' -Guidance @"
  -TenantId requested : $requested
  az signed in to     : $actual

This script creates an app registration, grants admin consent and assigns a
directory role, so it will not run against a tenant you did not name.

Sign in to the intended tenant and run it again:

  az login --tenant $requested --allow-no-subscriptions
"@
}

$tenantId = $signedInTenantId
$primaryDomain = if ($signedInDomain) { $signedInDomain } else { $tenantId }
Write-Step "Tenant: $primaryDomain ($tenantId)"

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
    try {
        $created = Invoke-Az -Arguments @(
            'ad', 'app', 'create', '--display-name', $AppName, '--sign-in-audience', 'AzureADMyOrg')
        $appId = $created.appId
    }
    catch {
        Stop-WithGuidance -Summary "Creating the app registration '$AppName' failed." -Guidance @"
$($_.Exception.Message)

The usual causes, in order:

  * Your account is not allowed to register applications. This step needs
    Application Developer or higher, and many tenants set
    "Users can register applications" to No, which blocks everyone else.
    Check who you are with:
      az ad signed-in-user show --query userPrincipalName

    Note that a later step needs more: granting admin consent for Microsoft
    Graph app roles requires Privileged Role Administrator. Application
    Administrator and Cloud Application Administrator are explicitly excluded
    from consenting to those, so starting with one of them will get you past
    this step and fail at consent instead.

  * Conditional Access or MFA needs a fresh sign-in for Microsoft Graph:
      az login --tenant $TenantId --allow-no-subscriptions

  * An app named '$AppName' already exists but is not visible to you, so it
    was neither reused nor creatable. Try a different -AppName.
"@
    }
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

# The root management group carries the tenant's own ID, and every subscription
# in the directory inherits from it — including ones created after this runs.
# One assignment here is the tenant-shaped equivalent of enumerating every
# subscription, which is why there is no per-subscription parameter.
$rootManagementGroupScope = "/providers/Microsoft.Management/managementGroups/$tenantId"
$azureRolesAssigned = $false

if ($TenantRootScope -and $servicePrincipalObjectId) {
    Write-Step 'Assigning Azure roles at the tenant root management group'

    foreach ($role in 'Reader', 'Security Reader') {
        if (-not $PSCmdlet.ShouldProcess($rootManagementGroupScope, "Assign '$role'")) { continue }

        $result = Invoke-Az -AllowFailure -Arguments @(
            'role', 'assignment', 'create',
            '--assignee-object-id', $servicePrincipalObjectId,
            '--assignee-principal-type', 'ServicePrincipal',
            '--role', $role, '--scope', $rootManagementGroupScope, '--only-show-errors')

        if ($result) {
            Write-Ok "  $role"
            $azureRolesAssigned = $true
        }
        else {
            Write-Warn "  $role assignment failed — it may already exist, or you lack access to the root management group."
            Write-Warn '  A Global Administrator must elevate access first: Entra ID > Properties > Access management for Azure resources.'
        }
    }
}
elseif (-not $TenantRootScope) {
    Write-Warn 'No -TenantRootScope — Azure and Sentinel sections will report as skipped. See the summary for how to grant this later.'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

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

if (-not $azureRolesAssigned) {
    Write-Host '  * Azure RBAC for the Azure and Sentinel sections. Graph permissions grant'
    Write-Host '    nothing over Azure resources, so those sections stay skipped until this'
    Write-Host '    is in place. One assignment at the tenant root covers every subscription,'
    Write-Host '    including future ones (a Global Administrator must elevate access first,'
    Write-Host '    under Entra ID > Properties > Access management for Azure resources):'
    Write-Host ''
    foreach ($role in 'Reader', 'Security Reader') {
        Write-Host "      az role assignment create --assignee-object-id $servicePrincipalObjectId ``"
        Write-Host "          --assignee-principal-type ServicePrincipal --role '$role' ``"
        Write-Host "          --scope $rootManagementGroupScope"
    }
    Write-Host ''
    Write-Host '    Or re-run this script with -TenantRootScope.'
}

Write-Host '  * Microsoft Sentinel Reader on any Sentinel workspace you want collected.'
