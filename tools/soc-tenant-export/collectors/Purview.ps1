<#
    Purview.ps1 — Microsoft Purview compliance configuration.

    Reached through Connect-IPPSSession rather than Exchange Online. Alert
    policies are the SOC-facing part: they are what raises a case in the first
    place, so their thresholds and recipients belong in the export.
#>

Set-StrictMode -Version Latest

Register-SocExchangeCollector -Name 'protection-alert-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-ProtectionAlert' `
    -Description 'Purview alert policies: trigger conditions, severity, thresholds and notification recipients. Disabled built-in policies are a common silent gap.'

Register-SocExchangeCollector -Name 'audit-configuration-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-AuditConfigurationPolicy' `
    -Description 'Audit configuration policies governing which workloads write to the unified audit log.'

Register-SocExchangeCollector -Name 'audit-retention-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-UnifiedAuditLogRetentionPolicy' `
    -Description 'Audit log retention policies. Retention shorter than the investigation window destroys evidence before it is needed.'

Register-SocExchangeCollector -Name 'dlp-compliance-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-DlpCompliancePolicy' `
    -Description 'Data loss prevention policies and the workloads they cover.'

Register-SocExchangeCollector -Name 'dlp-compliance-rules' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-DlpComplianceRule' `
    -Description 'DLP rule detail: conditions, sensitive information types, actions and incident report recipients.'

Register-SocExchangeCollector -Name 'retention-compliance-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-RetentionCompliancePolicy' `
    -Description 'Retention policies and the locations they apply to.'

Register-SocExchangeCollector -Name 'retention-compliance-rules' -Section 'Purview' -Transport 'Compliance' -Depth 'Extended' `
    -Cmdlet 'Get-RetentionComplianceRule' `
    -Description 'Retention rule detail, including retention duration and disposition.'

Register-SocExchangeCollector -Name 'compliance-tags' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-ComplianceTag' `
    -Description 'Retention labels available for manual and automatic application.'

Register-SocExchangeCollector -Name 'sensitivity-labels' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-Label' `
    -Description 'Sensitivity labels and their encryption and marking settings.'

Register-SocExchangeCollector -Name 'sensitivity-label-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-LabelPolicy' `
    -Description 'Which sensitivity labels are published to which users, and any mandatory labelling requirement.'

Register-SocExchangeCollector -Name 'supervisory-review-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-SupervisoryReviewPolicyV2' `
    -Description 'Communication compliance policies and their reviewers.'

Register-SocExchangeCollector -Name 'device-conditional-access-policies' -Section 'Purview' -Transport 'Compliance' `
    -Cmdlet 'Get-DeviceConditionalAccessPolicy' `
    -Description 'Legacy Intune-managed conditional access policies surfaced through the compliance endpoint.'
