#Requires -Version 7.0

<#
.SYNOPSIS
    Exports the security configuration of a Microsoft Entra ID / Microsoft 365 /
    Azure tenant for SOC review, baselining and drift detection.

.DESCRIPTION
    Produces a timestamped, self-describing snapshot of the settings a SOC relies
    on: Conditional Access, authentication methods, consent and privileged
    access, Intune compliance, Defender XDR and Defender for Office 365 policy,
    Exchange Online audit and mail flow, Purview alert policies, Defender for
    Cloud, and Microsoft Sentinel analytics and connectors.

    The script is strictly read-only. It issues GET requests and Get-* cmdlets
    only, and never modifies tenant state.

    Each artifact is written as JSON with provenance (source, collection time,
    item count) alongside a collection log and a Markdown summary. A collector
    that fails does not stop the run: it is recorded with a status explaining
    why, so gaps in an export are explicit rather than silent.

    Microsoft Graph and Azure Resource Manager are called over REST with tokens
    this script acquires itself, so no PowerShell modules are needed for those
    sections. The Defender for Office 365, Exchange Online and Purview sections
    have no Graph equivalent and require the ExchangeOnlineManagement module;
    they are reported as skipped if it is absent.

.PARAMETER TenantId
    Tenant GUID or a verified domain name. Required unless -ListArtifacts is used.

.PARAMETER OutputPath
    Directory that will receive the export folder. Defaults to ./soc-export.

.PARAMETER Include
    Only collect these sections. Defaults to all sections.

.PARAMETER Exclude
    Skip these sections. Applied after -Include.

.PARAMETER Depth
    Standard collects configuration and runs in bounded time. Extended adds
    enumerations that scale with tenant size (per-app owners, per-principal role
    assignments, devices, guest accounts) and takes considerably longer.

.PARAMETER AuthMode
    Certificate      App-only with a certificate. The recommended unattended
                     mode, and the only app-only mode Exchange Online supports.
    ClientSecret     App-only with a client secret. Graph, ARM and Defender only;
                     the Exchange and Purview sections cannot use it.
    DeviceCode       Delegated sign-in in a browser. Good for one-off runs.
    ExistingSession  Reuse an existing Connect-AzAccount context (Az.Accounts).

.PARAMETER ClientId
    Application (client) ID of the app registration. Required for the app-only
    modes; optional for DeviceCode, which otherwise uses the Microsoft Graph
    PowerShell first-party client.

.PARAMETER ClientSecret
    Client secret as a SecureString, for -AuthMode ClientSecret.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in CurrentUser\My or LocalMachine\My.

.PARAMETER CertificatePath
    Path to a PFX file, as an alternative to -CertificateThumbprint.

.PARAMETER CertificatePassword
    Password for the PFX supplied to -CertificatePath.

.PARAMETER SubscriptionId
    Restrict the Azure and Sentinel sections to these subscriptions. Defaults to
    every enabled subscription the credential can see.

.PARAMETER Environment
    Sovereign cloud to target. Defaults to Global.

.PARAMETER RedactUserData
    Replace personal identifiers (UPNs, mail addresses, phone numbers, names)
    with per-run pseudonyms. Correlation is preserved within an export, so a
    redacted copy can leave the customer boundary for peer review.

.PARAMETER Archive
    Also produce a .zip of the export folder.

.PARAMETER ListArtifacts
    Print the collector manifest with the permission each artifact needs, then
    exit. Requires no credentials — use it to scope an app registration.

.PARAMETER MaxRetryCount
    Attempts per throttled or transiently failed request. Defaults to 5.

.EXAMPLE
    ./Export-SocTenantSettings.ps1 -ListArtifacts

    Show every artifact and the permission it needs, without connecting.

.EXAMPLE
    ./Export-SocTenantSettings.ps1 -TenantId contoso.onmicrosoft.com

    Interactive device-code sign-in, all sections, Standard depth.

.EXAMPLE
    ./Export-SocTenantSettings.ps1 -TenantId contoso.onmicrosoft.com `
        -AuthMode Certificate -ClientId 00000000-1111-2222-3333-444444444444 `
        -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
        -Depth Extended -Archive

    Unattended app-only export of everything, zipped for attachment to a ticket.

.EXAMPLE
    ./Export-SocTenantSettings.ps1 -TenantId contoso.com -Include Entra,Applications -RedactUserData

    Identity configuration only, pseudonymised for sharing outside the customer.

.NOTES
    Read-only by design. See README.md for the app registration and permission
    matrix, and for what this export deliberately does not cover.
#>

[CmdletBinding()]
param(
    [string]$TenantId,

    [string]$OutputPath = (Join-Path (Get-Location).Path 'soc-export'),

    [ValidateSet('Entra', 'Applications', 'Governance', 'Intune', 'DefenderXdr',
        'DefenderOffice', 'ExchangeOnline', 'Purview', 'Azure', 'Sentinel')]
    [string[]]$Include,

    [ValidateSet('Entra', 'Applications', 'Governance', 'Intune', 'DefenderXdr',
        'DefenderOffice', 'ExchangeOnline', 'Purview', 'Azure', 'Sentinel')]
    [string[]]$Exclude,

    [ValidateSet('Standard', 'Extended')]
    [string]$Depth = 'Standard',

    [ValidateSet('DeviceCode', 'ClientSecret', 'Certificate', 'ExistingSession')]
    [string]$AuthMode = 'DeviceCode',

    [string]$ClientId,
    [securestring]$ClientSecret,
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [securestring]$CertificatePassword,

    [string[]]$SubscriptionId,

    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
    [string]$Environment = 'Global',

    [switch]$RedactUserData,
    [switch]$Archive,
    [switch]$ListArtifacts,

    [ValidateRange(1, 20)]
    [int]$MaxRetryCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SocScriptVersion = '1.0.0'

# ---------------------------------------------------------------------------
# Load framework and collectors
# ---------------------------------------------------------------------------

$root = $PSScriptRoot

# Order matters: Common defines helpers the others use at load time.
foreach ($file in 'Common.ps1', 'Auth.ps1', 'RestClient.ps1', 'ExchangeClient.ps1', 'Registry.ps1', 'Report.ps1') {
    . (Join-Path $root 'private' $file)
}

foreach ($file in (Get-ChildItem -Path (Join-Path $root 'collectors') -Filter '*.ps1' | Sort-Object Name)) {
    . $file.FullName
}

$script:SocMaxRetries = $MaxRetryCount

# ---------------------------------------------------------------------------
# -ListArtifacts: no credentials required
# ---------------------------------------------------------------------------

if ($ListArtifacts) {
    # Objects rather than a formatted table: this composes with Export-Csv and
    # Where-Object, and a table would render empty whenever stdout is redirected
    # (a redirected host reports a console width of -1).
    Get-SocSelectedCollectors -Include $Include -Exclude $Exclude -Depth 'Extended' |
        Select-Object Section, Name, Depth, Transport, Permission, Description

    Write-Host ("{0} artifacts registered ({1} at Standard depth). Pipe to Format-Table or Export-Csv to review." -f
        $script:SocCollectors.Count,
        @($script:SocCollectors | Where-Object { $_.Depth -eq 'Standard' }).Count) -ForegroundColor Cyan
    return
}

if (-not $TenantId) {
    throw 'A -TenantId is required. Pass a tenant GUID or a verified domain name, or use -ListArtifacts to inspect the manifest without connecting.'
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------

Write-SocLog -Level Step -Message "SOC tenant export v$script:SocScriptVersion — read-only"
Write-SocLog -Level Info -Message "Tenant: $TenantId  |  Cloud: $Environment  |  Auth: $AuthMode  |  Depth: $Depth"

Initialize-SocAuth -TenantId $TenantId -Environment $Environment -AuthMode $AuthMode `
    -ClientId $ClientId -ClientSecret $ClientSecret `
    -CertificateThumbprint $CertificateThumbprint `
    -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword

$context = New-SocRunContext -TenantId $TenantId -OutputPath $OutputPath -Depth $Depth `
    -Environment $Environment -AuthMode $AuthMode -RedactUserData:$RedactUserData
$context.Subscriptions = @($SubscriptionId)

New-Item -ItemType Directory -Path $context.Root -Force | Out-Null

# Tenant identity is needed for the report and for the Exchange Online
# -Organization parameter. A failure here is not fatal: the Azure-only sections
# do not need Graph at all.
try {
    $organization = @(Invoke-SocGraphRequest -Path '/organization')
    if ($organization.Count -gt 0) {
        $context.TenantName = Get-SocProperty $organization[0] 'displayName'
        $context.TenantId = Get-SocProperty $organization[0] 'id' $context.TenantId

        $verified = @(Get-SocProperty $organization[0] 'verifiedDomains')
        $initial = $verified | Where-Object { (Get-SocProperty $_ 'isInitial') -eq $true } | Select-Object -First 1
        if (-not $initial) {
            $initial = $verified | Where-Object { (Get-SocProperty $_ 'isDefault') -eq $true } | Select-Object -First 1
        }
        if ($initial) { $context.TenantDomain = Get-SocProperty $initial 'name' }

        Write-SocLog -Level Success -Message "Resolved tenant: $($context.TenantName) ($($context.TenantDomain))"
    }
}
catch {
    $detail = Get-SocErrorDetail -ErrorRecord $_
    $warning = "Could not resolve tenant identity from Microsoft Graph: $($detail.Message)"
    $context.Warnings.Add($warning)
    Write-SocLog -Level Warn -Message $warning
}

# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

$collectors = Get-SocSelectedCollectors -Include $Include -Exclude $Exclude -Depth $Depth
if ($collectors.Count -eq 0) {
    throw 'No collectors matched the selected sections and depth.'
}

Write-SocLog -Level Info -Message "Collecting $($collectors.Count) artifacts into $($context.Root)"

$selection = @{
    include = @($Include)
    exclude = @($Exclude)
    depth   = $Depth
    sections = @($collectors | Select-Object -ExpandProperty Section -Unique)
    subscriptionFilter = @($SubscriptionId)
}

try {
    Invoke-SocCollectorSet -Context $context -Collectors $collectors
}
finally {
    Disconnect-SocExchange
    Write-SocRunOutput -Context $context -Selection $selection
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$collected = @($context.Results | Where-Object { $_.status -eq 'Collected' }).Count
$empty = @($context.Results | Where-Object { $_.status -eq 'Empty' }).Count
$skipped = @($context.Results | Where-Object { $_.status -like 'Skipped*' }).Count
$failed = @($context.Results | Where-Object { $_.status -eq 'Failed' }).Count

Write-SocLog -Level Step -Message 'Export complete'
Write-SocLog -Level Info -Message "Collected: $collected  |  Empty: $empty  |  Skipped: $skipped  |  Failed: $failed"
Write-SocLog -Level Info -Message "Output: $($context.Root)"
Write-SocLog -Level Info -Message "Summary: $(Join-Path $context.Root 'summary.md')"

if ($failed -gt 0) {
    Write-SocLog -Level Warn -Message "$failed artifact(s) failed unexpectedly — see collection-log.json."
}

if ($Archive) {
    $zip = "$($context.Root).zip"
    Compress-Archive -Path $context.Root -DestinationPath $zip -Force
    Write-SocLog -Level Success -Message "Archive: $zip"
}

# Emit the export path so the script composes in a pipeline.
Get-Item -LiteralPath $context.Root
