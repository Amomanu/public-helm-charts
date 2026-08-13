<#
    RestClient.ps1 — shared HTTP plumbing for Microsoft Graph, Azure Resource
    Manager and the Defender for Endpoint API.

    All three APIs throttle aggressively and page differently; both concerns are
    handled once here so collectors stay declarative.
#>

Set-StrictMode -Version Latest

$script:SocMaxRetries = 5

# Hard ceiling on pages followed per artifact. Nothing in Graph or ARM should
# approach this; it exists so that a malformed or self-referential nextLink
# cannot hang an unattended export indefinitely.
$script:SocMaxPages = 1000

function Get-SocRetryAfterSeconds {
    <#
        .SYNOPSIS
            Extracts Retry-After from a failed response, falling back to
            exponential backoff when the service does not supply one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)][int]$Attempt
    )

    $fallback = [Math]::Min([Math]::Pow(2, $Attempt), 60)

    $response = Get-SocProperty $ErrorRecord.Exception 'Response'
    if (-not $response) { return $fallback }

    $headers = Get-SocProperty $response 'Headers'
    if (-not $headers) { return $fallback }

    # HttpResponseHeaders exposes a typed RetryAfter; raw header enumeration is
    # the fallback for other response types.
    $retryAfter = Get-SocProperty $headers 'RetryAfter'
    if ($retryAfter) {
        $delta = Get-SocProperty $retryAfter 'Delta'
        if ($delta) { return [int]$delta.TotalSeconds }
    }

    try {
        $values = $null
        if ($headers.TryGetValues('Retry-After', [ref]$values)) {
            $parsed = 0
            if ([int]::TryParse(@($values)[0], [ref]$parsed)) { return $parsed }
        }
    }
    catch {
        # Header collection does not support TryGetValues — use the fallback.
    }

    return $fallback
}

function Invoke-SocRestRequest {
    <#
        .SYNOPSIS
            Issues a single authenticated request with throttle-aware retries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet('Graph', 'Arm', 'Defender')][string]$Resource,
        [string]$Method = 'GET',
        [hashtable]$AdditionalHeaders
    )

    $attempt = 0
    while ($true) {
        $attempt++

        $headers = @{
            Authorization = 'Bearer ' + (Get-SocToken -Resource $Resource)
            Accept        = 'application/json'
        }
        if ($AdditionalHeaders) {
            foreach ($key in $AdditionalHeaders.Keys) { $headers[$key] = $AdditionalHeaders[$key] }
        }

        try {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ErrorAction Stop
        }
        catch {
            $detail = Get-SocErrorDetail -ErrorRecord $_
            $retryable = $detail.StatusCode -in 429, 500, 502, 503, 504

            if (-not $retryable -or $attempt -ge $script:SocMaxRetries) { throw }

            $wait = Get-SocRetryAfterSeconds -ErrorRecord $_ -Attempt $attempt
            Write-SocLog -Level Detail -Message "HTTP $($detail.StatusCode) — retrying in ${wait}s (attempt $attempt/$script:SocMaxRetries)"
            Start-Sleep -Seconds $wait
        }
    }
}

function Join-SocUri {
    <#
        .SYNOPSIS
            Appends query parameters, respecting any already present on the path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string[]]$Query
    )

    $parts = @($Query | Where-Object { $_ })
    if (-not $parts) { return $Uri }

    $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
    return $Uri + $separator + ($parts -join '&')
}

function Invoke-SocGraphRequest {
    <#
        .SYNOPSIS
            Calls Microsoft Graph and follows @odata.nextLink to completion.

        .PARAMETER Path
            Graph path beginning with '/', e.g. /identity/conditionalAccess/policies.

        .PARAMETER ApiVersion
            v1.0 (default) or beta. Several security-relevant resources are only
            exposed on beta; those collectors opt in explicitly.

        .PARAMETER Single
            Treat the response as one object rather than a collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0',
        [string]$Select,
        [string]$Filter,
        [string]$Expand,
        [int]$PageSize,
        [switch]$Single,
        [switch]$AdvancedQuery,
        [int]$MaxItems
    )

    $base = (Get-SocEndpoint -Name 'Graph').TrimEnd('/')
    $uri = "$base/$ApiVersion$Path"

    $query = @()
    if ($Select) { $query += '$select=' + $Select }
    if ($Filter) { $query += '$filter=' + [uri]::EscapeDataString($Filter) }
    if ($Expand) { $query += '$expand=' + $Expand }
    if ($PageSize) { $query += '$top=' + $PageSize }
    if ($AdvancedQuery) { $query += '$count=true' }
    $uri = Join-SocUri -Uri $uri -Query $query

    $headers = $null
    if ($AdvancedQuery) { $headers = @{ ConsistencyLevel = 'eventual' } }

    $first = Invoke-SocRestRequest -Uri $uri -Resource 'Graph' -AdditionalHeaders $headers

    if ($Single) { return $first }

    $items = [System.Collections.Generic.List[object]]::new()
    $page = $first
    $pageCount = 0
    while ($true) {
        $pageCount++
        # Presence of the value property, not its contents, decides whether this
        # is a collection response: an endpoint with nothing to return sends
        # {"value": []}, and PowerShell collapses that empty array to $null on
        # the way out of Get-SocProperty. Testing the value itself would treat
        # every empty collection as a bare object and store the raw envelope as
        # a phantom item.
        if (Test-SocProperty $page 'value') {
            foreach ($item in @(Get-SocProperty $page 'value')) { $items.Add($item) }
        }
        elseif ($null -ne $page) {
            # Endpoint returned a bare object where a collection was expected.
            $items.Add($page)
            break
        }

        if ($MaxItems -and $items.Count -ge $MaxItems) { break }

        $next = Get-SocProperty $page '@odata.nextLink'
        if (-not $next) { break }
        if ($pageCount -ge $script:SocMaxPages) {
            Write-SocLog -Level Warn -Message "Stopped after $script:SocMaxPages pages for $Path — result may be truncated."
            break
        }

        $page = Invoke-SocRestRequest -Uri $next -Resource 'Graph' -AdditionalHeaders $headers
    }

    return $items.ToArray()
}

function Invoke-SocArmRequest {
    <#
        .SYNOPSIS
            Calls Azure Resource Manager and follows nextLink to completion.

        .PARAMETER Path
            ARM path beginning with '/', e.g. /subscriptions/<id>/providers/...
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ApiVersion,
        [switch]$Single
    )

    $base = (Get-SocEndpoint -Name 'Arm').TrimEnd('/')
    $uri = Join-SocUri -Uri "$base$Path" -Query @("api-version=$ApiVersion")

    $first = Invoke-SocRestRequest -Uri $uri -Resource 'Arm'
    if ($Single) { return $first }

    $items = [System.Collections.Generic.List[object]]::new()
    $page = $first
    $pageCount = 0
    while ($true) {
        $pageCount++
        # Presence of the value property, not its contents, decides whether this
        # is a collection response: an endpoint with nothing to return sends
        # {"value": []}, and PowerShell collapses that empty array to $null on
        # the way out of Get-SocProperty. Testing the value itself would treat
        # every empty collection as a bare object and store the raw envelope as
        # a phantom item.
        if (Test-SocProperty $page 'value') {
            foreach ($item in @(Get-SocProperty $page 'value')) { $items.Add($item) }
        }
        elseif ($null -ne $page) {
            $items.Add($page)
            break
        }

        $next = Get-SocProperty $page 'nextLink'
        if (-not $next) { break }
        if ($pageCount -ge $script:SocMaxPages) {
            Write-SocLog -Level Warn -Message "Stopped after $script:SocMaxPages pages for $Path — result may be truncated."
            break
        }

        $page = Invoke-SocRestRequest -Uri $next -Resource 'Arm'
    }

    return $items.ToArray()
}

function Invoke-SocDefenderRequest {
    <#
        .SYNOPSIS
            Calls the Microsoft Defender for Endpoint API (api.securitycenter.*).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Single
    )

    $base = (Get-SocEndpoint -Name 'Defender').TrimEnd('/')
    $uri = "$base$Path"

    $first = Invoke-SocRestRequest -Uri $uri -Resource 'Defender'
    if ($Single) { return $first }

    $items = [System.Collections.Generic.List[object]]::new()
    $page = $first
    $pageCount = 0
    while ($true) {
        $pageCount++
        # Presence of the value property, not its contents, decides whether this
        # is a collection response: an endpoint with nothing to return sends
        # {"value": []}, and PowerShell collapses that empty array to $null on
        # the way out of Get-SocProperty. Testing the value itself would treat
        # every empty collection as a bare object and store the raw envelope as
        # a phantom item.
        if (Test-SocProperty $page 'value') {
            foreach ($item in @(Get-SocProperty $page 'value')) { $items.Add($item) }
        }
        elseif ($null -ne $page) {
            $items.Add($page)
            break
        }

        $next = Get-SocProperty $page '@odata.nextLink'
        if (-not $next) { break }
        if ($pageCount -ge $script:SocMaxPages) {
            Write-SocLog -Level Warn -Message "Stopped after $script:SocMaxPages pages for $Path — result may be truncated."
            break
        }

        $page = Invoke-SocRestRequest -Uri $next -Resource 'Defender'
    }

    return $items.ToArray()
}
