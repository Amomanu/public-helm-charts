<#
    DefenderOffice.ps1 — Exchange Online Protection and Defender for Office 365
    policy configuration.

    In PowerShell these features are split into a *policy* (the settings) and a
    *rule* (priority and recipient scope). Both halves are exported, because a
    strong policy attached to no recipients protects nobody.
#>

Set-StrictMode -Version Latest

# --- Anti-phishing -----------------------------------------------------------

Register-SocExchangeCollector -Name 'anti-phish-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-AntiPhishPolicy' `
    -Description 'Anti-phishing policies: impersonation protection, mailbox intelligence, spoof intelligence and safety tips.'

Register-SocExchangeCollector -Name 'anti-phish-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-AntiPhishRule' `
    -Description 'Recipient scope and priority for each anti-phishing policy.'

# --- Anti-spam ---------------------------------------------------------------

Register-SocExchangeCollector -Name 'hosted-content-filter-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-HostedContentFilterPolicy' `
    -Description 'Inbound anti-spam policies, including bulk threshold, allowed sender/domain lists and quarantine actions.'

Register-SocExchangeCollector -Name 'hosted-content-filter-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-HostedContentFilterRule' `
    -Description 'Recipient scope and priority for each inbound anti-spam policy.'

Register-SocExchangeCollector -Name 'outbound-spam-filter-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-HostedOutboundSpamFilterPolicy' `
    -Description 'Outbound spam policies, including recipient limits and automatic forwarding control — a key BEC exfiltration path.'

Register-SocExchangeCollector -Name 'outbound-spam-filter-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-HostedOutboundSpamFilterRule' `
    -Description 'Sender scope and priority for each outbound spam policy.'

# --- Anti-malware ------------------------------------------------------------

Register-SocExchangeCollector -Name 'malware-filter-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-MalwareFilterPolicy' `
    -Description 'Anti-malware policies and the common attachment type filter.'

Register-SocExchangeCollector -Name 'malware-filter-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-MalwareFilterRule' `
    -Description 'Recipient scope and priority for each anti-malware policy.'

# --- Safe Links / Safe Attachments -------------------------------------------

Register-SocExchangeCollector -Name 'safe-links-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-SafeLinksPolicy' `
    -Description 'Safe Links policies: URL rewriting and time-of-click protection for mail, Teams and Office apps.'

Register-SocExchangeCollector -Name 'safe-links-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-SafeLinksRule' `
    -Description 'Recipient scope and priority for each Safe Links policy.'

Register-SocExchangeCollector -Name 'safe-attachment-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-SafeAttachmentPolicy' `
    -Description 'Safe Attachments policies and the action taken on detonated malware.'

Register-SocExchangeCollector -Name 'safe-attachment-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-SafeAttachmentRule' `
    -Description 'Recipient scope and priority for each Safe Attachments policy.'

Register-SocExchangeCollector -Name 'atp-policy-for-o365' -Section 'DefenderOffice' `
    -Cmdlet 'Get-AtpPolicyForO365' `
    -Description 'Safe Attachments for SharePoint, OneDrive and Teams, plus Safe Documents.'

# --- Preset security policies ------------------------------------------------

Register-SocExchangeCollector -Name 'eop-protection-policy-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-EOPProtectionPolicyRule' `
    -Description 'Standard/Strict preset security policy assignment for EOP protections.'

Register-SocExchangeCollector -Name 'atp-protection-policy-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-ATPProtectionPolicyRule' `
    -Description 'Standard/Strict preset security policy assignment for Defender for Office 365 protections.'

# --- Overrides and allow/block lists -----------------------------------------

Register-SocCollector -Name 'tenant-allow-block-list' -Section 'DefenderOffice' -Transport 'Exchange' `
    -Permission 'Get-TenantAllowBlockListItems (PowerShell)' `
    -Description 'Tenant allow/block list entries across all list types. Allow entries are a deliberate detection gap and should be reviewed for expiry.' `
    -Script {
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($listType in 'Sender', 'Url', 'FileHash', 'IP') {
        try {
            $items = Invoke-SocExchangeCmdlet -Name 'Get-TenantAllowBlockListItems' -Parameters @{ ListType = $listType }
            foreach ($item in @($items)) {
                $output.Add([pscustomobject]@{ listType = $listType; entry = $item })
            }
        }
        catch {
            $output.Add([pscustomobject]@{
                    listType = $listType
                    entry    = $null
                    error    = (Get-SocErrorDetail -ErrorRecord $_).Message
                })
        }
    }

    return $output.ToArray()
}

Register-SocExchangeCollector -Name 'tenant-allow-block-list-spoof' -Section 'DefenderOffice' `
    -Cmdlet 'Get-TenantAllowBlockListSpoofItems' `
    -Description 'Spoofed sender allow/block entries from spoof intelligence.'

Register-SocExchangeCollector -Name 'phish-simulation-override-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-PhishSimOverridePolicy' `
    -Description 'Third-party phishing simulation overrides. These bypass filtering, so an unexpected entry is an attacker-friendly gap.'

Register-SocExchangeCollector -Name 'phish-simulation-override-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-PhishSimOverrideRule' `
    -Description 'Sender domains and IPs allowed to bypass filtering for phishing simulations.'

Register-SocExchangeCollector -Name 'secops-override-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-ExoSecOpsOverridePolicy' `
    -Description 'SecOps mailbox override policy — mail to these mailboxes skips filtering.'

Register-SocExchangeCollector -Name 'secops-override-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-ExoSecOpsOverrideRule' `
    -Description 'Mailboxes designated as SecOps mailboxes and therefore exempt from filtering.'

# --- Quarantine and user reporting -------------------------------------------

Register-SocExchangeCollector -Name 'quarantine-policies' -Section 'DefenderOffice' `
    -Cmdlet 'Get-QuarantinePolicy' `
    -Description 'Quarantine policies controlling what end users may do with quarantined messages.'

Register-SocExchangeCollector -Name 'report-submission-policy' -Section 'DefenderOffice' `
    -Cmdlet 'Get-ReportSubmissionPolicy' `
    -Description 'User reported message settings — whether reports reach Microsoft, a custom mailbox, or both.'

Register-SocExchangeCollector -Name 'report-submission-rules' -Section 'DefenderOffice' `
    -Cmdlet 'Get-ReportSubmissionRule' `
    -Description 'Reporting mailbox routing for user reported messages.'

# --- Authentication of mail --------------------------------------------------

Register-SocExchangeCollector -Name 'dkim-signing-config' -Section 'DefenderOffice' `
    -Cmdlet 'Get-DkimSigningConfig' `
    -Description 'DKIM signing state and selector configuration per accepted domain.'
