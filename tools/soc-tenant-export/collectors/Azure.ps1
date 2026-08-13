<#
    Azure.ps1 — Azure control-plane security configuration.

    Two questions drive this section: is Defender for Cloud actually turned on,
    and are the logs a SOC depends on being shipped anywhere. The Entra
    diagnostic settings collector answers the second for identity telemetry and
    is the single most consequential artifact here.
#>

Set-StrictMode -Version Latest

function Get-SocSubscriptionList {
    <#
        .SYNOPSIS
            Enabled subscriptions visible to the caller, narrowed by
            -SubscriptionId when supplied.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    return Get-SocCached -Context $Context -Key 'subscriptions' -Factory {
        $subscriptions = Invoke-SocArmRequest -Path '/subscriptions' -ApiVersion '2022-12-01'

        if ($Context.Subscriptions -and @($Context.Subscriptions).Count -gt 0) {
            $subscriptions = $subscriptions | Where-Object {
                (Get-SocProperty $_ 'subscriptionId') -in $Context.Subscriptions
            }
        }

        @($subscriptions | Where-Object { (Get-SocProperty $_ 'state') -eq 'Enabled' })
    }
}

function Invoke-SocPerSubscription {
    <#
        .SYNOPSIS
            Runs a per-subscription query and tags each row with its subscription.

        .DESCRIPTION
            One subscription failing (an unregistered resource provider, a
            missing RBAC assignment) must not lose the results from the others,
            so failures are recorded inline as rows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][scriptblock]$Script
    )

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($subscription in (Get-SocSubscriptionList -Context $Context)) {
        $id = Get-SocProperty $subscription 'subscriptionId'
        $name = Get-SocProperty $subscription 'displayName'

        try {
            foreach ($row in @(& $Script $id)) {
                $output.Add([pscustomobject]@{
                        subscriptionId   = $id
                        subscriptionName = $name
                        value            = $row
                    })
            }
        }
        catch {
            $detail = Get-SocErrorDetail -ErrorRecord $_
            $output.Add([pscustomobject]@{
                    subscriptionId   = $id
                    subscriptionName = $name
                    value            = $null
                    error            = "$($detail.ServiceCode): $($detail.Message)"
                })
        }
    }

    return $output.ToArray()
}

# ---------------------------------------------------------------------------
# Tenant scope
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'entra-diagnostic-settings' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Reader on the tenant root, or Security Reader' `
    -Description 'Where Entra ID sign-in and audit logs are exported. Without a destination here, sign-in logs are retained only for the Entra default period and there is nothing for Sentinel to query.' `
    -Script { Invoke-SocArmRequest -Path '/providers/microsoft.aadiam/diagnosticSettings' -ApiVersion '2017-04-01-preview' }

Register-SocCollector -Name 'subscriptions' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Reader' `
    -Description 'Subscriptions in scope for this export.' `
    -Script {
    param($Context)
    Get-SocSubscriptionList -Context $Context
}

# ---------------------------------------------------------------------------
# Microsoft Defender for Cloud
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'defender-for-cloud-pricings' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Which Defender for Cloud plans are enabled per subscription, and at which sub-plan.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings" -ApiVersion '2024-01-01'
    }
}

Register-SocCollector -Name 'defender-for-cloud-security-contacts' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Who receives Defender for Cloud alert notifications, and at what severity. An empty contact list means alerts go nowhere.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityContacts" -ApiVersion '2020-01-01-preview'
    }
}

Register-SocCollector -Name 'defender-for-cloud-auto-provisioning' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Automatic agent provisioning settings for new resources.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/autoProvisioningSettings" -ApiVersion '2017-08-01-preview'
    }
}

Register-SocCollector -Name 'defender-for-cloud-settings' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Defender for Cloud data export toggles, including the Defender for Endpoint and Defender for Cloud Apps integrations.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/settings" -ApiVersion '2022-05-01'
    }
}

Register-SocCollector -Name 'defender-for-cloud-workspace-settings' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Which Log Analytics workspace Defender for Cloud sends data to.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/workspaceSettings" -ApiVersion '2017-08-01-preview'
    }
}

Register-SocCollector -Name 'defender-for-cloud-alert-suppression-rules' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Alert suppression rules. Each one silences a detection, so every rule needs a documented reason and an expiry.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/alertsSuppressionRules" -ApiVersion '2019-01-01-preview'
    }
}

Register-SocCollector -Name 'defender-for-cloud-automations' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Workflow automations that forward Defender for Cloud alerts to Logic Apps, Event Hubs or webhooks.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/automations" -ApiVersion '2019-01-01-preview'
    }
}

Register-SocCollector -Name 'defender-for-cloud-secure-scores' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Defender for Cloud secure score per subscription.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores" -ApiVersion '2020-01-01'
    }
}

Register-SocCollector -Name 'regulatory-compliance-standards' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Security Reader' `
    -Description 'Regulatory compliance standards assigned in Defender for Cloud and their pass/fail counts.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/regulatoryComplianceStandards" -ApiVersion '2019-01-01-preview'
    }
}

# ---------------------------------------------------------------------------
# Governance and monitoring
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'policy-assignments' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Reader' `
    -Description 'Azure Policy assignments, including the Microsoft cloud security benchmark initiative and any deny or audit effects.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/policyAssignments" -ApiVersion '2023-04-01'
    }
}

Register-SocCollector -Name 'subscription-diagnostic-settings' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Reader' `
    -Description 'Activity log export settings per subscription — whether control-plane events reach a workspace, storage account or event hub.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/diagnosticSettings" -ApiVersion '2021-05-01-preview'
    }
}

Register-SocCollector -Name 'activity-log-alerts' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Reader' `
    -Description 'Activity log alert rules — control-plane alerting on events such as security policy changes.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/activityLogAlerts" -ApiVersion '2020-10-01'
    }
}

Register-SocCollector -Name 'log-analytics-workspaces' -Section 'Azure' -Transport 'Arm' `
    -Permission 'Reader' `
    -Description 'Log Analytics workspaces with retention and access-control mode. Retention below the investigation window limits hunting.' `
    -Script {
    param($Context)
    Get-SocLogAnalyticsWorkspaceList -Context $Context
}

Register-SocCollector -Name 'azure-role-assignments' -Section 'Azure' -Transport 'Arm' -Depth 'Extended' `
    -Permission 'Reader (User Access Administrator for complete results)' `
    -Description 'Azure RBAC assignments at subscription scope and below.' `
    -Script {
    param($Context)
    Invoke-SocPerSubscription -Context $Context -Script {
        param($SubscriptionId)
        Invoke-SocArmRequest -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments" -ApiVersion '2022-04-01'
    }
}

function Get-SocLogAnalyticsWorkspaceList {
    <#
        .SYNOPSIS
            All Log Analytics workspaces in scope. Shared with the Sentinel
            collectors, which need the same list to find onboarded workspaces.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    return Get-SocCached -Context $Context -Key 'logAnalyticsWorkspaces' -Factory {
        $output = [System.Collections.Generic.List[object]]::new()

        foreach ($subscription in (Get-SocSubscriptionList -Context $Context)) {
            $id = Get-SocProperty $subscription 'subscriptionId'
            try {
                $workspaces = Invoke-SocArmRequest `
                    -Path "/subscriptions/$id/providers/Microsoft.OperationalInsights/workspaces" `
                    -ApiVersion '2022-10-01'
            }
            catch {
                continue
            }

            foreach ($workspace in @($workspaces)) {
                $output.Add([pscustomobject]@{
                        subscriptionId   = $id
                        subscriptionName = Get-SocProperty $subscription 'displayName'
                        workspaceId      = Get-SocProperty $workspace 'id'
                        name             = Get-SocProperty $workspace 'name'
                        location         = Get-SocProperty $workspace 'location'
                        properties       = Get-SocProperty $workspace 'properties'
                    })
            }
        }

        $output.ToArray()
    }
}
