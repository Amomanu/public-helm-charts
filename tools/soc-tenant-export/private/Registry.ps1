<#
    Registry.ps1 — the collector manifest and the runner that drives it.

    Every artifact in the export is one registered collector. Adding coverage
    means adding a Register-SocCollector call; the runner handles transport
    setup, timing, error classification and persistence uniformly.
#>

Set-StrictMode -Version Latest

$script:SocCollectors = [System.Collections.Generic.List[object]]::new()

# Order controls both execution order and the layout of the summary report.
$script:SocSectionOrder = @(
    'Entra', 'Applications', 'Governance', 'Intune',
    'DefenderXdr', 'DefenderOffice', 'ExchangeOnline', 'Purview',
    'Azure', 'Sentinel'
)

function Register-SocCollector {
    <#
        .SYNOPSIS
            Declares one exportable artifact.

        .PARAMETER Transport
            Which connection the collector needs. The runner establishes
            Exchange/Compliance sessions lazily, and only if some selected
            collector actually needs them.

        .PARAMETER Depth
            Standard collectors are configuration and run in bounded time.
            Extended collectors enumerate objects that scale with tenant size
            (applications, devices, role assignments) and only run with
            -Depth Extended.

        .PARAMETER Script
            Receives the run context and returns the data to persist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][ValidateSet('Graph', 'Arm', 'Defender', 'Exchange', 'Compliance')][string]$Transport,
        [Parameter(Mandatory)][scriptblock]$Script,
        [string]$Description,
        [string]$Permission,
        [ValidateSet('Standard', 'Extended')][string]$Depth = 'Standard'
    )

    $script:SocCollectors.Add([pscustomobject]@{
            Name        = $Name
            Section     = $Section
            Transport   = $Transport
            Script      = $Script
            Description = $Description
            Permission  = $Permission
            Depth       = $Depth
        })
}

function Register-SocExchangeCollector {
    <#
        .SYNOPSIS
            Shorthand for the many collectors that are a single Exchange or
            Security & Compliance cmdlet with no arguments.

        .DESCRIPTION
            GetNewClosure captures the cmdlet name and parameters at registration
            time; without it every registered scriptblock would resolve the loop
            variable to whatever it held last.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Cmdlet,
        [Parameter(Mandatory)][string]$Description,
        [ValidateSet('Exchange', 'Compliance')][string]$Transport = 'Exchange',
        [ValidateSet('Standard', 'Extended')][string]$Depth = 'Standard',
        [hashtable]$Parameters = @{}
    )

    $capturedCmdlet = $Cmdlet
    $capturedParameters = $Parameters

    Register-SocCollector -Name $Name -Section $Section -Transport $Transport -Depth $Depth `
        -Permission "$Cmdlet (PowerShell)" -Description $Description `
        -Script ({ Invoke-SocExchangeCmdlet -Name $capturedCmdlet -Parameters $capturedParameters }.GetNewClosure())
}

function Get-SocSelectedCollectors {
    <#
        .SYNOPSIS
            Applies -Include/-Exclude/-Depth to the manifest.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Include,
        [string[]]$Exclude,
        [string]$Depth = 'Standard'
    )

    $selected = $script:SocCollectors

    if ($Include) {
        $selected = $selected | Where-Object { $_.Section -in $Include }
    }
    if ($Exclude) {
        $selected = $selected | Where-Object { $_.Section -notin $Exclude }
    }
    if ($Depth -eq 'Standard') {
        $selected = $selected | Where-Object { $_.Depth -eq 'Standard' }
    }

    $order = $script:SocSectionOrder
    return @($selected | Sort-Object @{ Expression = { $order.IndexOf($_.Section) } }, Name)
}

function Initialize-SocTransport {
    <#
        .SYNOPSIS
            Ensures the session a collector needs exists.

        .OUTPUTS
            $null when the transport is ready, otherwise the reason it is not.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Transport
    )

    switch ($Transport) {
        'Exchange' {
            if (Connect-SocExchangeOnline -Context $Context) { return $null }
            return $script:SocExchangeState.ExchangeSkipReason
        }
        'Compliance' {
            if (Connect-SocCompliance -Context $Context) { return $null }
            return $script:SocExchangeState.ComplianceSkipReason
        }
        default { return $null }
    }
}

function Invoke-SocCollectorSet {
    <#
        .SYNOPSIS
            Runs the selected collectors, persisting each result and recording an
            outcome per artifact.

        .DESCRIPTION
            A collector failure never stops the export. Each artifact records one
            of: Collected, Empty, SkippedNoPermission, SkippedNotLicensed,
            SkippedNotFound, SkippedUnsupported, SkippedNoTransport or Failed —
            so a partial export is still trustworthy evidence, and the gaps are
            explicit rather than silent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][object[]]$Collectors
    )

    $total = $Collectors.Count
    $index = 0
    $currentSection = $null

    foreach ($collector in $Collectors) {
        $index++

        if ($collector.Section -ne $currentSection) {
            $currentSection = $collector.Section
            Write-SocLog -Level Step -Message "Section: $currentSection"
        }

        $result = [ordered]@{
            artifact    = $collector.Name
            section     = $collector.Section
            transport   = $collector.Transport
            depth       = $collector.Depth
            description = $collector.Description
            permission  = $collector.Permission
            status      = 'Failed'
            itemCount   = 0
            durationMs  = 0
            file        = $null
            error       = $null
        }

        $transportIssue = Initialize-SocTransport -Context $Context -Transport $collector.Transport
        if ($transportIssue) {
            $result.status = 'SkippedNoTransport'
            $result.error = $transportIssue
            Write-SocLog -Level Warn -Message ("[{0}/{1}] {2} — skipped ({3})" -f $index, $total, $collector.Name, $transportIssue)
            $Context.Results.Add([pscustomobject]$result)
            continue
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $data = & $collector.Script $Context

            $saved = Save-SocArtifact -Context $Context -Domain $collector.Section -Name $collector.Name `
                -Data $data -Source $collector.Permission -Description $collector.Description

            $result.itemCount = $saved.Count
            $result.file = [IO.Path]::GetRelativePath($Context.Root, $saved.Path)
            $result.status = if ($saved.Count -eq 0) { 'Empty' } else { 'Collected' }

            $level = if ($saved.Count -eq 0) { 'Detail' } else { 'Success' }
            Write-SocLog -Level $level -Message ("[{0}/{1}] {2} — {3} item(s)" -f $index, $total, $collector.Name, $saved.Count)
        }
        catch {
            $detail = Get-SocErrorDetail -ErrorRecord $_
            $result.status = Get-SocSkipReason -Detail $detail
            $result.error = $detail.Message
            if ($detail.ServiceCode) { $result.error = "$($detail.ServiceCode): $($detail.Message)" }

            $level = if ($result.status -eq 'Failed') { 'Error' } else { 'Warn' }
            Write-SocLog -Level $level -Message ("[{0}/{1}] {2} — {3}: {4}" -f $index, $total, $collector.Name, $result.status, $result.error)
        }
        finally {
            $stopwatch.Stop()
            $result.durationMs = [int]$stopwatch.ElapsedMilliseconds
        }

        $Context.Results.Add([pscustomobject]$result)
    }
}
