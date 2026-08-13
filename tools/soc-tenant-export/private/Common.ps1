<#
    Common.ps1 — logging, run context, artifact persistence and redaction.

    Dot-sourced by Export-SocTenantSettings.ps1. Not intended to run standalone.
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Run context
# ---------------------------------------------------------------------------

function New-SocRunContext {
    <#
        .SYNOPSIS
            Creates the state object that every collector writes through.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$Depth,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string]$AuthMode,
        [switch]$RedactUserData
    )

    $started = Get-Date
    $stamp = $started.ToUniversalTime().ToString('yyyyMMdd-HHmmssZ')
    $root = Join-Path $OutputPath ('{0}_{1}' -f (ConvertTo-SocSafeFileName $TenantId), $stamp)

    [pscustomobject]@{
        TenantId       = $TenantId
        TenantName     = $null
        TenantDomain   = $null
        Root           = $root
        Depth          = $Depth
        Environment    = $Environment
        AuthMode       = $AuthMode
        RedactUserData = [bool]$RedactUserData
        # Random per-run salt so pseudonyms correlate inside one export but not across exports.
        RedactionSalt  = [Guid]::NewGuid().ToString()
        StartedUtc     = $started.ToUniversalTime()
        Results        = [System.Collections.Generic.List[object]]::new()
        ObjectNameMap  = @{}
        # Shared between collectors so expensive enumerations (service
        # principals, subscriptions, workspaces) are fetched once per run.
        Cache          = @{}
        Subscriptions  = @()
        Warnings       = [System.Collections.Generic.List[string]]::new()
        ScriptVersion  = $script:SocScriptVersion
    }
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-SocLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [ValidateSet('Info', 'Step', 'Success', 'Warn', 'Error', 'Detail')]
        [string]$Level = 'Info'
    )

    $ts = (Get-Date).ToUniversalTime().ToString('HH:mm:ss')
    $prefix, $colour = switch ($Level) {
        'Step' { '==>', 'Cyan' }
        'Success' { ' ok', 'Green' }
        'Warn' { ' ! ', 'Yellow' }
        'Error' { 'ERR', 'Red' }
        'Detail' { '   ', 'DarkGray' }
        default { '   ', 'Gray' }
    }

    # Host output is intentional: this is an operator-facing tool, and the data
    # itself goes to files rather than the pipeline.
    Write-Host ('[{0}] {1} {2}' -f $ts, $prefix, $Message) -ForegroundColor $colour
}

function Get-SocProperty {
    <#
        .SYNOPSIS
            Reads an optional property without tripping Set-StrictMode.

        .DESCRIPTION
            API responses omit properties routinely, and strict mode turns every
            such access into a terminating error. Every read of a service
            response goes through here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowNull()]$InputObject,
        [Parameter(Mandatory, Position = 1)][string]$Name,
        [Parameter(Position = 2)]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }

    $prop = $InputObject.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function Test-SocProperty {
    <#
        .SYNOPSIS
            Reports whether a property is present, regardless of its value.

        .DESCRIPTION
            Get-SocProperty cannot answer this: PowerShell unrolls collections on
            return, so a property holding an empty array comes back as $null and
            is indistinguishable from a property that does not exist. That
            distinction matters for API responses, where {"value": []} means "an
            empty collection" and no value property at all means "a single
            object".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowNull()]$InputObject,
        [Parameter(Mandatory, Position = 1)][string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-SocCached {
    <#
        .SYNOPSIS
            Memoises an expensive enumeration for the lifetime of the run.

        .DESCRIPTION
            Several collectors need the same underlying list (service principals,
            subscriptions, Log Analytics workspaces). Fetching once keeps large
            tenants from paying for the same pagination repeatedly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][scriptblock]$Factory
    )

    if (-not $Context.Cache.ContainsKey($Key)) {
        $Context.Cache[$Key] = & $Factory
    }

    return $Context.Cache[$Key]
}

function Get-SocErrorDetail {
    <#
        .SYNOPSIS
            Flattens an ErrorRecord into a message plus, where present, the HTTP
            status and the service's own error code.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $status = $null
    $serviceCode = $null
    $message = $ErrorRecord.Exception.Message

    $response = $null
    if ($ErrorRecord.Exception.PSObject.Properties.Name -contains 'Response') {
        $response = $ErrorRecord.Exception.Response
    }
    if ($response -and $response.PSObject.Properties.Name -contains 'StatusCode') {
        $status = [int]$response.StatusCode
    }

    # PS7 surfaces the response body here for Invoke-RestMethod failures.
    $body = $null
    if ($ErrorRecord.PSObject.Properties.Name -contains 'ErrorDetails' -and $ErrorRecord.ErrorDetails) {
        $body = $ErrorRecord.ErrorDetails.Message
    }
    if ($body) {
        try {
            $parsed = $body | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.PSObject.Properties.Name -contains 'error') {
                $err = $parsed.error
                if ($err -is [string]) {
                    $serviceCode = $err
                }
                else {
                    if ($err.PSObject.Properties.Name -contains 'code') { $serviceCode = $err.code }
                    if ($err.PSObject.Properties.Name -contains 'message') { $message = $err.message }
                }
            }
        }
        catch {
            # Non-JSON error body — keep the raw text, trimmed.
            if ($body.Length -gt 500) { $message = $body.Substring(0, 500) } else { $message = $body }
        }
    }

    [pscustomobject]@{
        Message     = $message
        StatusCode  = $status
        ServiceCode = $serviceCode
    }
}

function Get-SocSkipReason {
    <#
        .SYNOPSIS
            Maps a failure to a stable status so the collection log distinguishes
            "you lack permission" from "this tenant isn't licensed" from "broken".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Detail)

    $code = $Detail.ServiceCode
    $status = $Detail.StatusCode
    $text = "$($Detail.Message) $code"

    if ($status -in 401, 403) { return 'SkippedNoPermission' }
    if ($code -in 'Authorization_RequestDenied', 'Authorization_RequestDenied_Legacy', 'AuthorizationFailed', 'Forbidden') {
        return 'SkippedNoPermission'
    }
    if ($status -eq 404) { return 'SkippedNotFound' }
    if ($code -in 'ResourceNotFound', 'SubscriptionNotFound', 'NotFound') { return 'SkippedNotFound' }
    if ($text -match 'license|not licensed|subscription.*not.*found|tenant.*not.*onboard|does not have.*plan|Premium') {
        return 'SkippedNotLicensed'
    }
    if ($status -eq 501 -or $code -eq 'NotImplemented') { return 'SkippedUnsupported' }

    return 'Failed'
}

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Property names replaced with a stable pseudonym when -RedactUserData is set.
$script:SocRedactProperties = @(
    'userPrincipalName', 'mail', 'mailNickname', 'otherMails', 'proxyAddresses',
    'givenName', 'surname', 'employeeId', 'mobilePhone', 'businessPhones',
    'faxNumber', 'streetAddress', 'postalCode', 'onPremisesSamAccountName',
    'onPremisesUserPrincipalName', 'onPremisesImmutableId', 'imAddresses',
    'PrimarySmtpAddress', 'WindowsLiveID', 'UserPrincipalName', 'EmailAddresses'
)

function Get-SocPseudonym {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Salt
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes("$Salt|$Value")
        $hash = [Convert]::ToHexString($sha.ComputeHash($bytes)).Substring(0, 12).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }

    if ($Value -match '@') { return "redacted-$hash@redacted.invalid" }
    return "redacted-$hash"
}

function Protect-SocData {
    <#
        .SYNOPSIS
            Recursively pseudonymises personal identifiers so an export can leave
            the customer boundary. Correlation is preserved within a single run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Salt,
        [int]$CurrentDepth = 0
    )

    if ($null -eq $InputObject -or $CurrentDepth -gt 32) { return $InputObject }

    # Value types (primitives, enums, DateTime, Guid, TimeSpan, decimal) and
    # strings are leaves — nothing to walk into.
    if ($InputObject -is [string] -or $InputObject.GetType().IsValueType) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $copy = @{}
        foreach ($key in @($InputObject.Keys)) {
            if ($key -in $script:SocRedactProperties) {
                $copy[$key] = Convert-SocRedactedValue -Value $InputObject[$key] -Salt $Salt
            }
            else {
                $copy[$key] = Protect-SocData -InputObject $InputObject[$key] -Salt $Salt -CurrentDepth ($CurrentDepth + 1)
            }
        }
        return $copy
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        return @(foreach ($item in $InputObject) {
                Protect-SocData -InputObject $item -Salt $Salt -CurrentDepth ($CurrentDepth + 1)
            })
    }

    if ($InputObject -is [psobject]) {
        $copy = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            if ($prop.Name -in $script:SocRedactProperties) {
                $copy[$prop.Name] = Convert-SocRedactedValue -Value $prop.Value -Salt $Salt
            }
            else {
                $copy[$prop.Name] = Protect-SocData -InputObject $prop.Value -Salt $Salt -CurrentDepth ($CurrentDepth + 1)
            }
        }
        return [pscustomobject]$copy
    }

    return $InputObject
}

function Convert-SocRedactedValue {
    [CmdletBinding()]
    param([AllowNull()]$Value, [Parameter(Mandatory)][string]$Salt)

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return Get-SocPseudonym -Value $Value -Salt $Salt }
    if ($Value -is [System.Collections.IEnumerable]) {
        return @(foreach ($item in $Value) {
                if ($item -is [string]) { Get-SocPseudonym -Value $item -Salt $Salt } else { $item }
            })
    }
    return $Value
}

# ---------------------------------------------------------------------------
# Artifact persistence
# ---------------------------------------------------------------------------

function ConvertTo-SocSafeFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    $safe = $Name -replace '[^\w\.\-]', '-'
    $safe = $safe -replace '-{2,}', '-'
    return $safe.Trim('-').ToLowerInvariant()
}

function Save-SocArtifact {
    <#
        .SYNOPSIS
            Writes one collected artifact to disk as JSON and records its outcome.

        .DESCRIPTION
            Every artifact lands in <root>/<domain>/<name>.json. The wrapper adds
            provenance (source path/cmdlet, collection time, item count) so an
            export is self-describing months later during an investigation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowNull()]$Data,
        [string]$Source,
        [string]$Description
    )

    $dir = Join-Path $Context.Root (ConvertTo-SocSafeFileName $Domain)
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $payload = $Data
    if ($Context.RedactUserData) {
        $payload = Protect-SocData -InputObject $payload -Salt $Context.RedactionSalt
    }

    $count = 0
    if ($null -ne $payload) {
        if ($payload -is [System.Collections.IEnumerable] -and $payload -isnot [string] -and
            $payload -isnot [System.Collections.IDictionary]) {
            $count = @($payload).Count
        }
        else {
            $count = 1
        }
    }

    $wrapper = [ordered]@{
        artifact      = $Name
        domain        = $Domain
        description   = $Description
        source        = $Source
        tenantId      = $Context.TenantId
        collectedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        itemCount     = $count
        redacted      = $Context.RedactUserData
        scriptVersion = $Context.ScriptVersion
        value         = $payload
    }

    $file = Join-Path $dir ((ConvertTo-SocSafeFileName $Name) + '.json')
    $json = $wrapper | ConvertTo-Json -Depth 64 -WarningAction SilentlyContinue
    Set-Content -LiteralPath $file -Value $json -Encoding utf8NoBOM

    return [pscustomobject]@{ Path = $file; Count = $count }
}
