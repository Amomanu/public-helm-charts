<#
    Sentinel.ps1 — Microsoft Sentinel workspace configuration.

    Every Log Analytics workspace in scope is probed for Sentinel onboarding;
    only onboarded workspaces are queried further. Analytics rules and data
    connectors together answer the question a SOC actually cares about: what is
    being ingested, and what is being detected on it.
#>

Set-StrictMode -Version Latest

# Bump this to pick up newer resource types. Kept as one constant so an API
# version change is a single edit rather than a sweep through the collectors.
$script:SocSentinelApiVersion = '2024-09-01'

function Get-SocSentinelWorkspaceList {
    <#
        .SYNOPSIS
            Log Analytics workspaces that have Sentinel onboarded.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    return Get-SocCached -Context $Context -Key 'sentinelWorkspaces' -Factory {
        $output = [System.Collections.Generic.List[object]]::new()

        foreach ($workspace in (Get-SocLogAnalyticsWorkspaceList -Context $Context)) {
            $resourceId = $workspace.workspaceId
            try {
                $onboarding = Invoke-SocArmRequest -Single `
                    -Path "$resourceId/providers/Microsoft.SecurityInsights/onboardingStates/default" `
                    -ApiVersion $script:SocSentinelApiVersion
            }
            catch {
                # 404 simply means Sentinel is not enabled on this workspace.
                continue
            }

            $output.Add([pscustomobject]@{
                    subscriptionId = $workspace.subscriptionId
                    workspaceName  = $workspace.name
                    workspaceId    = $resourceId
                    location       = $workspace.location
                    onboardingState = $onboarding
                })
        }

        $output.ToArray()
    }
}

function Invoke-SocPerSentinelWorkspace {
    <#
        .SYNOPSIS
            Runs a Sentinel sub-resource query against every onboarded workspace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$ResourceType,
        [string]$ApiVersion
    )

    if (-not $ApiVersion) { $ApiVersion = $script:SocSentinelApiVersion }

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($workspace in (Get-SocSentinelWorkspaceList -Context $Context)) {
        try {
            $items = Invoke-SocArmRequest `
                -Path "$($workspace.workspaceId)/providers/Microsoft.SecurityInsights/$ResourceType" `
                -ApiVersion $ApiVersion

            foreach ($item in @($items)) {
                $output.Add([pscustomobject]@{
                        subscriptionId = $workspace.subscriptionId
                        workspaceName  = $workspace.workspaceName
                        value          = $item
                    })
            }
        }
        catch {
            $detail = Get-SocErrorDetail -ErrorRecord $_
            $output.Add([pscustomobject]@{
                    subscriptionId = $workspace.subscriptionId
                    workspaceName  = $workspace.workspaceName
                    value          = $null
                    error          = "$($detail.ServiceCode): $($detail.Message)"
                })
        }
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'sentinel-workspaces' -Section 'Sentinel' -Transport 'Arm' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Log Analytics workspaces with Microsoft Sentinel enabled, and their onboarding state.' `
    -Script {
    param($Context)
    Get-SocSentinelWorkspaceList -Context $Context
}

Register-SocCollector -Name 'sentinel-analytics-rules' -Section 'Sentinel' -Transport 'Arm' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Analytics rules with query, scheduling, severity, MITRE mapping and incident grouping. Disabled rules are included — a disabled rule is a detection gap.' `
    -Script {
    param($Context)
    Invoke-SocPerSentinelWorkspace -Context $Context -ResourceType 'alertRules'
}

Register-SocCollector -Name 'sentinel-data-connectors' -Section 'Sentinel' -Transport 'Arm' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Configured data connectors and which data types each one streams. Defines the tenant visibility ceiling.' `
    -Script {
    param($Context)
    Invoke-SocPerSentinelWorkspace -Context $Context -ResourceType 'dataConnectors'
}

Register-SocCollector -Name 'sentinel-automation-rules' -Section 'Sentinel' -Transport 'Arm' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Automation rules — incident triage automation, including any rule that auto-closes incidents.' `
    -Script {
    param($Context)
    Invoke-SocPerSentinelWorkspace -Context $Context -ResourceType 'automationRules'
}

Register-SocCollector -Name 'sentinel-settings' -Section 'Sentinel' -Transport 'Arm' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Workspace-level Sentinel settings such as UEBA, anomalies and entity behaviour analytics.' `
    -Script {
    param($Context)
    Invoke-SocPerSentinelWorkspace -Context $Context -ResourceType 'settings'
}

Register-SocCollector -Name 'sentinel-watchlists' -Section 'Sentinel' -Transport 'Arm' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Watchlists used for enrichment and allow-listing in analytics rules.' `
    -Script {
    param($Context)
    Invoke-SocPerSentinelWorkspace -Context $Context -ResourceType 'watchlists'
}

Register-SocCollector -Name 'sentinel-content-packages' -Section 'Sentinel' -Transport 'Arm' -Depth 'Extended' `
    -Permission 'Microsoft Sentinel Reader' `
    -Description 'Installed content hub solutions and their versions.' `
    -Script {
    param($Context)
    Invoke-SocPerSentinelWorkspace -Context $Context -ResourceType 'contentPackages'
}
