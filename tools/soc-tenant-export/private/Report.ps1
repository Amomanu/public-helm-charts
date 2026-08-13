<#
    Report.ps1 — run manifest, collection log and the human-readable summary.

    The summary derives strictly from what was collected. Anything that was not
    collected is reported as "not collected" rather than assumed good: a
    posture report that silently treats a permission failure as a pass is worse
    than no report at all.
#>

Set-StrictMode -Version Latest

# Guest role template IDs, from most to least permissive.
$script:SocGuestRoleNames = @{
    'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same as member user (most permissive)'
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Guest user (default)'
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted guest user (most restrictive)'
}

function Get-SocArtifactValue {
    <#
        .SYNOPSIS
            Reads back a persisted artifact so the summary works from exactly the
            same data the operator will read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Name
    )

    $file = Join-Path $Context.Root (ConvertTo-SocSafeFileName $Domain) ((ConvertTo-SocSafeFileName $Name) + '.json')
    if (-not (Test-Path -LiteralPath $file)) { return $null }

    try {
        $content = Get-Content -LiteralPath $file -Raw -Encoding utf8
        $parsed = $content | ConvertFrom-Json -Depth 64
        return Get-SocProperty $parsed 'value'
    }
    catch {
        return $null
    }
}

function New-SocHighlight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Check,
        # A missing setting arrives as $null or '' depending on the branch; both
        # mean "not collected" rather than a binding failure.
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Finding,
        [string]$Artifact
    )

    [pscustomobject]@{
        Check    = $Check
        Finding  = if ([string]::IsNullOrWhiteSpace($Finding)) { 'Not collected' } else { $Finding }
        Artifact = $Artifact
    }
}

function Get-SocPostureHighlights {
    <#
        .SYNOPSIS
            Derives a short list of high-signal posture facts from the export.

        .DESCRIPTION
            Deliberately factual: each row states what the configuration is and
            which artifact it came from. Judging whether a value is acceptable is
            left to the analyst and the engagement's baseline.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    $highlights = [System.Collections.Generic.List[object]]::new()

    # --- Security defaults ---------------------------------------------------
    $securityDefaults = Get-SocArtifactValue -Context $Context -Domain 'Entra' -Name 'security-defaults'
    $highlights.Add((New-SocHighlight -Check 'Security defaults' -Artifact 'entra/security-defaults.json' -Finding $(
                if ($securityDefaults) {
                    $enabled = Get-SocProperty $securityDefaults 'isEnabled'
                    if ($enabled -eq $true) { 'Enabled' } elseif ($enabled -eq $false) { 'Disabled' } else { 'Unknown' }
                }
            )))

    # --- Conditional Access --------------------------------------------------
    $caPolicies = Get-SocArtifactValue -Context $Context -Domain 'Entra' -Name 'conditional-access-policies'
    if ($null -ne $caPolicies) {
        $all = @($caPolicies)
        $enabled = @($all | Where-Object { (Get-SocProperty $_ 'state') -eq 'enabled' })
        $reportOnly = @($all | Where-Object { (Get-SocProperty $_ 'state') -eq 'enabledForReportingButNotEnforced' })
        $disabled = @($all | Where-Object { (Get-SocProperty $_ 'state') -eq 'disabled' })

        $highlights.Add((New-SocHighlight -Check 'Conditional Access policies' -Artifact 'entra/conditional-access-policies.json' `
                    -Finding ('{0} total — {1} enabled, {2} report-only, {3} disabled' -f $all.Count, $enabled.Count, $reportOnly.Count, $disabled.Count)))

        # A legacy-auth block policy targets the legacy client app types with a block grant.
        $legacyBlock = @($enabled | Where-Object {
                $conditions = Get-SocProperty $_ 'conditions'
                $clientApps = @(Get-SocProperty $conditions 'clientAppTypes')
                $grant = Get-SocProperty $_ 'grantControls'
                $controls = @(Get-SocProperty $grant 'builtInControls')
                ($clientApps -contains 'exchangeActiveSync' -or $clientApps -contains 'other') -and
                ($clientApps -notcontains 'all') -and ($controls -contains 'block')
            })
        $highlights.Add((New-SocHighlight -Check 'Legacy authentication blocked by CA' -Artifact 'entra/conditional-access-policies.json' `
                    -Finding $(
                        if ($legacyBlock.Count -eq 0) { 'No enabled policy matched the legacy-auth block pattern' }
                        elseif ($legacyBlock.Count -eq 1) { 'Yes — matched by 1 enabled policy' }
                        else { "Yes — matched by $($legacyBlock.Count) enabled policies" }
                    )))
    }
    else {
        $highlights.Add((New-SocHighlight -Check 'Conditional Access policies' -Finding $null -Artifact 'entra/conditional-access-policies.json'))
    }

    # --- Consent and guest access -------------------------------------------
    $authorization = Get-SocArtifactValue -Context $Context -Domain 'Entra' -Name 'authorization-policy'
    if ($null -ne $authorization) {
        $policy = @($authorization)[0]
        $defaults = Get-SocProperty $policy 'defaultUserRolePermissions'

        $consentPolicies = @(Get-SocProperty $defaults 'permissionGrantPoliciesAssigned')
        $highlights.Add((New-SocHighlight -Check 'User consent to applications' -Artifact 'entra/authorization-policy.json' `
                    -Finding $(if ($consentPolicies.Count -eq 0) { 'Disabled — users cannot consent' } else { $consentPolicies -join ', ' })))

        $highlights.Add((New-SocHighlight -Check 'Users may register applications' -Artifact 'entra/authorization-policy.json' `
                    -Finding ('{0}' -f (Get-SocProperty $defaults 'allowedToCreateApps'))))

        $guestRole = Get-SocProperty $policy 'guestUserRoleId'
        $guestName = if ($guestRole -and $script:SocGuestRoleNames.ContainsKey($guestRole)) { $script:SocGuestRoleNames[$guestRole] } else { $guestRole }
        $highlights.Add((New-SocHighlight -Check 'Guest user access level' -Artifact 'entra/authorization-policy.json' -Finding $guestName))
    }

    # --- Privileged roles ----------------------------------------------------
    $roles = Get-SocArtifactValue -Context $Context -Domain 'Entra' -Name 'directory-roles-with-members'
    if ($null -ne $roles) {
        $globalAdmin = @($roles | Where-Object { (Get-SocProperty $_ 'displayName') -eq 'Global Administrator' })
        $count = if ($globalAdmin.Count -gt 0) { Get-SocProperty $globalAdmin[0] 'memberCount' } else { $null }
        $highlights.Add((New-SocHighlight -Check 'Global Administrator members' -Artifact 'entra/directory-roles-with-members.json' `
                    -Finding $(if ($null -ne $count) { "$count" } else { 'Role not activated in the directory' })))
    }

    # --- MFA registration ----------------------------------------------------
    $registration = Get-SocArtifactValue -Context $Context -Domain 'Entra' -Name 'authentication-method-registration-summary'
    if ($null -ne $registration) {
        $summary = @($registration)[0]
        $total = Get-SocProperty $summary 'totalUserCount' 'unknown'
        $featureCounts = @(Get-SocProperty $summary 'userRegistrationFeatureCounts')

        $mfaEntry = $featureCounts | Where-Object { (Get-SocProperty $_ 'feature') -eq 'mfaRegistered' } | Select-Object -First 1
        $mfaCount = if ($mfaEntry) { Get-SocProperty $mfaEntry 'userCount' } else { 'unknown' }

        $highlights.Add((New-SocHighlight -Check 'Users registered for MFA' -Artifact 'entra/authentication-method-registration-summary.json' `
                    -Finding ('{0} of {1} users' -f $mfaCount, $total)))
    }

    # --- Credentials ---------------------------------------------------------
    $credentials = Get-SocArtifactValue -Context $Context -Domain 'Applications' -Name 'credential-expiry'
    if ($null -ne $credentials) {
        $rows = @($credentials)
        $expired = @($rows | Where-Object { (Get-SocProperty $_ 'state') -eq 'Expired' })
        $soon = @($rows | Where-Object { (Get-SocProperty $_ 'state') -eq 'ExpiringWithin30Days' })
        $highlights.Add((New-SocHighlight -Check 'Application credentials' -Artifact 'applications/credential-expiry.json' `
                    -Finding ('{0} total — {1} expired, {2} expiring within 30 days' -f $rows.Count, $expired.Count, $soon.Count)))
    }

    # --- Delegated consent ---------------------------------------------------
    $grants = Get-SocArtifactValue -Context $Context -Domain 'Applications' -Name 'oauth2-permission-grants'
    if ($null -ne $grants) {
        $rows = @($grants)
        $allPrincipals = @($rows | Where-Object { (Get-SocProperty $_ 'consentType') -eq 'AllPrincipals' })
        $highlights.Add((New-SocHighlight -Check 'Delegated permission grants' -Artifact 'applications/oauth2-permission-grants.json' `
                    -Finding ('{0} total — {1} granted tenant-wide (AllPrincipals)' -f $rows.Count, $allPrincipals.Count)))
    }

    # --- Unified audit log ---------------------------------------------------
    $auditConfig = Get-SocArtifactValue -Context $Context -Domain 'ExchangeOnline' -Name 'admin-audit-log-config'
    if ($null -ne $auditConfig) {
        $config = @($auditConfig)[0]
        $ingestion = Get-SocProperty $config 'UnifiedAuditLogIngestionEnabled'
        $highlights.Add((New-SocHighlight -Check 'Unified audit log ingestion' -Artifact 'exchangeonline/admin-audit-log-config.json' `
                    -Finding $(if ($ingestion -eq $true) { 'Enabled' } elseif ($ingestion -eq $false) { 'DISABLED — no searchable audit evidence' } else { 'Unknown' })))
    }

    $bypass = Get-SocArtifactValue -Context $Context -Domain 'ExchangeOnline' -Name 'mailbox-audit-bypass'
    if ($null -ne $bypass) {
        $highlights.Add((New-SocHighlight -Check 'Mailbox audit bypass entries' -Artifact 'exchangeonline/mailbox-audit-bypass.json' `
                    -Finding ('{0} account(s) exempt from mailbox auditing' -f @($bypass).Count)))
    }

    # --- Log routing ---------------------------------------------------------
    $entraDiagnostics = Get-SocArtifactValue -Context $Context -Domain 'Azure' -Name 'entra-diagnostic-settings'
    if ($null -ne $entraDiagnostics) {
        $settings = @($entraDiagnostics)
        $highlights.Add((New-SocHighlight -Check 'Entra ID log export' -Artifact 'azure/entra-diagnostic-settings.json' `
                    -Finding $(if ($settings.Count -gt 0) { "$($settings.Count) diagnostic setting(s) configured" } else { 'NONE — sign-in and audit logs are not exported' })))
    }

    # --- Defender for Cloud --------------------------------------------------
    $pricings = Get-SocArtifactValue -Context $Context -Domain 'Azure' -Name 'defender-for-cloud-pricings'
    if ($null -ne $pricings) {
        $rows = @($pricings | Where-Object { $null -ne (Get-SocProperty $_ 'value') })
        $standard = @($rows | Where-Object {
                $properties = Get-SocProperty (Get-SocProperty $_ 'value') 'properties'
                (Get-SocProperty $properties 'pricingTier') -eq 'Standard'
            })
        $highlights.Add((New-SocHighlight -Check 'Defender for Cloud plans' -Artifact 'azure/defender-for-cloud-pricings.json' `
                    -Finding ('{0} of {1} plan entries on the Standard tier' -f $standard.Count, $rows.Count)))
    }

    # --- Sentinel ------------------------------------------------------------
    $rules = Get-SocArtifactValue -Context $Context -Domain 'Sentinel' -Name 'sentinel-analytics-rules'
    if ($null -ne $rules) {
        $rows = @($rules | Where-Object { $null -ne (Get-SocProperty $_ 'value') })
        $enabledRules = @($rows | Where-Object {
                $properties = Get-SocProperty (Get-SocProperty $_ 'value') 'properties'
                (Get-SocProperty $properties 'enabled') -eq $true
            })
        $highlights.Add((New-SocHighlight -Check 'Sentinel analytics rules' -Artifact 'sentinel/sentinel-analytics-rules.json' `
                    -Finding ('{0} rule(s) — {1} enabled' -f $rows.Count, $enabledRules.Count)))
    }

    return $highlights.ToArray()
}

function Write-SocRunOutput {
    <#
        .SYNOPSIS
            Writes manifest.json, collection-log.json/.csv and summary.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][hashtable]$Selection
    )

    $finished = (Get-Date).ToUniversalTime()
    $results = @($Context.Results)

    $statusCounts = [ordered]@{}
    foreach ($group in ($results | Group-Object -Property status | Sort-Object Name)) {
        $statusCounts[$group.Name] = $group.Count
    }

    # --- manifest.json -------------------------------------------------------
    $manifest = [ordered]@{
        tenantId       = $Context.TenantId
        tenantName     = $Context.TenantName
        tenantDomain   = $Context.TenantDomain
        environment    = $Context.Environment
        authMode       = $Context.AuthMode
        depth          = $Context.Depth
        redacted       = $Context.RedactUserData
        scriptVersion  = $Context.ScriptVersion
        startedUtc     = $Context.StartedUtc.ToString('o')
        finishedUtc    = $finished.ToString('o')
        durationSeconds = [int]($finished - $Context.StartedUtc).TotalSeconds
        host           = [ordered]@{
            powerShellVersion = $PSVersionTable.PSVersion.ToString()
            os                = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
            machine           = [System.Environment]::MachineName
            user              = [System.Environment]::UserName
        }
        selection      = $Selection
        artifactCount  = $results.Count
        statusCounts   = $statusCounts
        warnings       = @($Context.Warnings)
    }
    $manifest | ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath (Join-Path $Context.Root 'manifest.json') -Encoding utf8NoBOM

    # --- collection log ------------------------------------------------------
    $results | ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath (Join-Path $Context.Root 'collection-log.json') -Encoding utf8NoBOM

    $results |
        Select-Object section, artifact, status, itemCount, durationMs, transport, depth, file, error |
        Export-Csv -LiteralPath (Join-Path $Context.Root 'collection-log.csv') -NoTypeInformation -Encoding utf8NoBOM

    # --- summary.md ----------------------------------------------------------
    $highlights = Get-SocPostureHighlights -Context $Context
    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add('# SOC configuration export')
    $lines.Add('')
    $lines.Add(('**Tenant:** {0} (`{1}`)' -f $Context.TenantName, $Context.TenantId))
    $lines.Add("**Primary domain:** $($Context.TenantDomain)")
    $lines.Add("**Collected:** $($Context.StartedUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    $lines.Add("**Duration:** $([int]($finished - $Context.StartedUtc).TotalSeconds)s")
    $lines.Add("**Depth:** $($Context.Depth)  |  **Cloud:** $($Context.Environment)  |  **Auth:** $($Context.AuthMode)")
    if ($Context.RedactUserData) {
        $lines.Add('**Redaction:** personal identifiers replaced with per-run pseudonyms.')
    }
    $lines.Add('')
    $lines.Add('All timestamps in this export are UTC. This is a read-only export; nothing was modified in the tenant.')
    $lines.Add('')

    $lines.Add('## Collection status')
    $lines.Add('')
    $lines.Add('| Status | Artifacts |')
    $lines.Add('|---|---|')
    foreach ($key in $statusCounts.Keys) {
        $lines.Add("| $key | $($statusCounts[$key]) |")
    }
    $lines.Add('')

    $lines.Add('## Posture highlights')
    $lines.Add('')
    $lines.Add('Derived strictly from the artifacts named below. "Not collected" means the export could not read that setting — treat it as unknown, not as compliant.')
    $lines.Add('')
    $lines.Add('| Check | Finding | Artifact |')
    $lines.Add('|---|---|---|')
    foreach ($highlight in $highlights) {
        $lines.Add("| $($highlight.Check) | $($highlight.Finding) | ``$($highlight.Artifact)`` |")
    }
    $lines.Add('')

    $problems = @($results | Where-Object { $_.status -notin 'Collected', 'Empty' })
    if ($problems.Count -gt 0) {
        $lines.Add('## Gaps in this export')
        $lines.Add('')
        $lines.Add('| Section | Artifact | Status | Reason |')
        $lines.Add('|---|---|---|---|')
        foreach ($problem in $problems) {
            $reason = ($problem.error -replace '\|', '\|') -replace '\r?\n', ' '
            if ($reason -and $reason.Length -gt 160) { $reason = $reason.Substring(0, 160) + '…' }
            $lines.Add("| $($problem.section) | $($problem.artifact) | $($problem.status) | $reason |")
        }
        $lines.Add('')
    }

    $lines.Add('## Artifacts collected')
    $lines.Add('')
    foreach ($section in ($results | Where-Object { $_.status -in 'Collected', 'Empty' } | Group-Object section)) {
        $lines.Add("### $($section.Name)")
        $lines.Add('')
        $lines.Add('| Artifact | Items | File |')
        $lines.Add('|---|---|---|')
        foreach ($item in ($section.Group | Sort-Object artifact)) {
            $lines.Add("| $($item.artifact) | $($item.itemCount) | ``$($item.file)`` |")
        }
        $lines.Add('')
    }

    Set-Content -LiteralPath (Join-Path $Context.Root 'summary.md') -Value ($lines -join [Environment]::NewLine) -Encoding utf8NoBOM
}
