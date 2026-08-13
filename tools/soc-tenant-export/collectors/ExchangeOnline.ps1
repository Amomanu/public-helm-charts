<#
    ExchangeOnline.ps1 — Exchange Online organisation, audit and mail flow
    configuration.

    Two things here matter more than the rest for a SOC: whether unified audit
    logging is on (without it there is no mailbox evidence to investigate), and
    anything that quietly moves mail out of the tenant.
#>

Set-StrictMode -Version Latest

# --- Organisation and audit --------------------------------------------------

Register-SocExchangeCollector -Name 'organization-config' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-OrganizationConfig' `
    -Description 'Exchange organisation settings, including AuditDisabled, modern authentication and client access defaults.'

Register-SocExchangeCollector -Name 'admin-audit-log-config' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-AdminAuditLogConfig' `
    -Description 'Unified audit log ingestion state. If UnifiedAuditLogIngestionEnabled is false, sign-in and mailbox activity is not searchable.'

Register-SocExchangeCollector -Name 'transport-config' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-TransportConfig' `
    -Description 'Organisation-wide transport settings, including journaling and message size limits.'

Register-SocCollector -Name 'mailbox-audit-bypass' -Section 'ExchangeOnline' -Transport 'Exchange' `
    -Permission 'Get-MailboxAuditBypassAssociation (PowerShell)' `
    -Description 'Accounts exempted from mailbox audit logging. Any enabled entry is a deliberate blind spot and should be justified.' `
    -Script {
    $all = Invoke-SocExchangeCmdlet -Name 'Get-MailboxAuditBypassAssociation' -Parameters @{ ResultSize = 'Unlimited' }
    return @($all | Where-Object { (Get-SocProperty $_ 'AuditBypassEnabled') -eq $true })
}

# --- Authentication ----------------------------------------------------------

Register-SocExchangeCollector -Name 'authentication-policies' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-AuthenticationPolicy' `
    -Description 'Authentication policies controlling legacy protocol access (IMAP, POP, SMTP AUTH, EWS). Legacy auth bypasses MFA.'

Register-SocExchangeCollector -Name 'organization-relationships' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-OrganizationRelationship' `
    -Description 'Federation relationships with other organisations and the free/busy and delegation they permit.'

Register-SocExchangeCollector -Name 'sharing-policies' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-SharingPolicy' `
    -Description 'Calendar and contact sharing permitted with external domains.'

# --- Mail flow ---------------------------------------------------------------

Register-SocExchangeCollector -Name 'transport-rules' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-TransportRule' `
    -Description 'Mail flow rules. Rules that bypass spam filtering, redirect mail, or blind-copy an external address warrant close review.'

Register-SocExchangeCollector -Name 'accepted-domains' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-AcceptedDomain' `
    -Description 'Accepted domains and their type. Authoritative versus internal relay changes how unknown recipients are handled.'

Register-SocExchangeCollector -Name 'remote-domains' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-RemoteDomain' `
    -Description 'Remote domain settings. AutoForwardEnabled on the default domain permits mailbox auto-forwarding out of the tenant.'

Register-SocExchangeCollector -Name 'inbound-connectors' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-InboundConnector' `
    -Description 'Inbound connectors. A connector trusting an unexpected partner or IP range can deliver unfiltered mail.'

Register-SocExchangeCollector -Name 'outbound-connectors' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-OutboundConnector' `
    -Description 'Outbound connectors, including any that route mail through third-party infrastructure.'

Register-SocExchangeCollector -Name 'journal-rules' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-JournalRule' `
    -Description 'Journal rules and their journaling recipients.'

Register-SocExchangeCollector -Name 'arc-config' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-ArcConfig' `
    -Description 'Trusted ARC sealers. A wrongly trusted sealer lets a third party assert authentication results.'

Register-SocExchangeCollector -Name 'external-sender-identification' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-ExternalInOutlook' `
    -Description 'Native external sender tagging in Outlook, and any senders excluded from it.'

Register-SocExchangeCollector -Name 'blocked-sender-addresses' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-BlockedSenderAddress' `
    -Description 'Accounts blocked from sending mail — typically the aftermath of a compromised mailbox sending spam.'

# --- Client access and delegation --------------------------------------------

Register-SocExchangeCollector -Name 'owa-mailbox-policies' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-OwaMailboxPolicy' `
    -Description 'Outlook on the web policies, including attachment handling and third-party storage integration.'

Register-SocExchangeCollector -Name 'activesync-organization-settings' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-ActiveSyncOrganizationSettings' `
    -Description 'Default access level for new Exchange ActiveSync devices.'

Register-SocExchangeCollector -Name 'mobile-device-mailbox-policies' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-MobileDeviceMailboxPolicy' `
    -Description 'Mobile device mailbox policies and their password and encryption requirements.'

Register-SocExchangeCollector -Name 'role-assignment-policies' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-RoleAssignmentPolicy' `
    -Description 'Default end-user role assignment policy — what users may configure for themselves, including app consent.'

Register-SocExchangeCollector -Name 'role-groups' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-RoleGroup' `
    -Description 'Exchange role groups and their members — the Exchange-side administrative privilege inventory.'

Register-SocExchangeCollector -Name 'management-role-assignments' -Section 'ExchangeOnline' -Depth 'Extended' `
    -Cmdlet 'Get-ManagementRoleAssignment' `
    -Description 'Every management role assignment, including those granted directly to users rather than through role groups.'

Register-SocExchangeCollector -Name 'app-only-service-principals' -Section 'ExchangeOnline' `
    -Cmdlet 'Get-ServicePrincipal' `
    -Description 'Service principals registered in Exchange for app-only access, which can hold mailbox-level permissions.'
