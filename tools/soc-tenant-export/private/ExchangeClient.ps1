<#
    ExchangeClient.ps1 — connection handling for Exchange Online and the
    Security & Compliance (Purview) endpoint.

    These are the only collectors that need a PowerShell module rather than REST:
    the Defender for Office 365, Exchange and Purview policy surfaces have no
    equivalent Graph coverage.
#>

Set-StrictMode -Version Latest

$script:SocExchangeState = @{
    ExchangeConnected   = $false
    ComplianceConnected = $false
    ExchangeSkipReason  = $null
    ComplianceSkipReason = $null
}

# Exchange deserialisation noise that adds size without adding evidence.
$script:SocExchangeNoiseProperties = @(
    'RunspaceId', 'PSComputerName', 'PSShowComputerName', 'PSSourceJobInstanceId',
    'ObjectState', 'ObjectCategory', 'OriginatingServer', 'ExchangeVersion'
)

function Test-SocExchangeModule {
    [CmdletBinding()]
    param()

    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) { return $true }
    return $false
}

function Connect-SocExchangeOnline {
    <#
        .SYNOPSIS
            Connects to Exchange Online, reusing the session for later collectors.

        .DESCRIPTION
            Exchange Online app-only authentication supports certificates only —
            there is no client-secret path — so a ClientSecret run reports these
            sections as skipped rather than failing them one by one.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    if ($script:SocExchangeState.ExchangeConnected) { return $true }
    if ($script:SocExchangeState.ExchangeSkipReason) { return $false }

    if (-not (Test-SocExchangeModule)) {
        $script:SocExchangeState.ExchangeSkipReason =
            'ExchangeOnlineManagement module not installed (Install-Module ExchangeOnlineManagement -Scope CurrentUser).'
        return $false
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $organization = $Context.TenantDomain
    if (-not $organization) { $organization = $Context.TenantId }

    $common = @{
        ShowBanner    = $false
        ErrorAction   = 'Stop'
        WarningAction = 'SilentlyContinue'
    }
    $envName = Get-SocEndpoint -Name 'ExoEnv'
    if ($envName -and $envName -ne 'O365Default') { $common['ExchangeEnvironmentName'] = $envName }

    try {
        switch ($script:SocAuth.AuthMode) {
            'Certificate' {
                Connect-ExchangeOnline @common -AppId $script:SocAuth.ClientId `
                    -Certificate $script:SocAuth.Certificate -Organization $organization
            }
            'ClientSecret' {
                $script:SocExchangeState.ExchangeSkipReason =
                    'Exchange Online app-only auth requires a certificate; -AuthMode ClientSecret cannot reach these cmdlets.'
                return $false
            }
            default {
                Connect-ExchangeOnline @common
            }
        }
    }
    catch {
        $script:SocExchangeState.ExchangeSkipReason = "Connect-ExchangeOnline failed: $($_.Exception.Message)"
        return $false
    }

    $script:SocExchangeState.ExchangeConnected = $true
    Write-SocLog -Level Success -Message 'Connected to Exchange Online.'
    return $true
}

function Connect-SocCompliance {
    <#
        .SYNOPSIS
            Connects to the Security & Compliance PowerShell endpoint for the
            Purview policy collectors.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    if ($script:SocExchangeState.ComplianceConnected) { return $true }
    if ($script:SocExchangeState.ComplianceSkipReason) { return $false }

    if (-not (Test-SocExchangeModule)) {
        $script:SocExchangeState.ComplianceSkipReason =
            'ExchangeOnlineManagement module not installed (Install-Module ExchangeOnlineManagement -Scope CurrentUser).'
        return $false
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $organization = $Context.TenantDomain
    if (-not $organization) { $organization = $Context.TenantId }

    try {
        switch ($script:SocAuth.AuthMode) {
            'Certificate' {
                Connect-IPPSSession -AppId $script:SocAuth.ClientId `
                    -Certificate $script:SocAuth.Certificate -Organization $organization `
                    -ErrorAction Stop -WarningAction SilentlyContinue
            }
            'ClientSecret' {
                $script:SocExchangeState.ComplianceSkipReason =
                    'Security & Compliance app-only auth requires a certificate; -AuthMode ClientSecret cannot reach these cmdlets.'
                return $false
            }
            default {
                Connect-IPPSSession -ErrorAction Stop -WarningAction SilentlyContinue
            }
        }
    }
    catch {
        $script:SocExchangeState.ComplianceSkipReason = "Connect-IPPSSession failed: $($_.Exception.Message)"
        return $false
    }

    $script:SocExchangeState.ComplianceConnected = $true
    Write-SocLog -Level Success -Message 'Connected to Security & Compliance PowerShell.'
    return $true
}

function Invoke-SocExchangeCmdlet {
    <#
        .SYNOPSIS
            Runs an Exchange/Compliance cmdlet and strips deserialisation noise.

        .DESCRIPTION
            Missing cmdlets are treated as "not available in this tenant" rather
            than as failures: the Defender for Office 365 cmdlets only exist with
            the corresponding licence, and Purview cmdlets vary by plan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [hashtable]$Parameters = @{}
    )

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Cmdlet '$Name' is not available in this session (feature not licensed, or insufficient role)."
    }

    $result = & $Name @Parameters -ErrorAction Stop

    if ($null -eq $result) { return @() }

    return @($result | Select-Object -Property * -ExcludeProperty $script:SocExchangeNoiseProperties)
}

function Disconnect-SocExchange {
    [CmdletBinding()]
    param()

    if ($script:SocExchangeState.ExchangeConnected -or $script:SocExchangeState.ComplianceConnected) {
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
        catch {
            Write-SocLog -Level Detail -Message "Exchange disconnect reported: $($_.Exception.Message)"
        }
        $script:SocExchangeState.ExchangeConnected = $false
        $script:SocExchangeState.ComplianceConnected = $false
    }
}
