<#
    Governance.ps1 — identity governance configuration.

    Access reviews and entitlement management define who is supposed to hold
    access and how that is re-certified; both are Entra ID P2 features and are
    reported as not licensed when absent.
#>

Set-StrictMode -Version Latest

Register-SocCollector -Name 'access-review-definitions' -Section 'Governance' -Transport 'Graph' `
    -Permission 'AccessReview.Read.All' `
    -Description 'Access review schedule definitions — what is recertified, by whom, and on what cadence.' `
    -Script { Invoke-SocGraphRequest -Path '/identityGovernance/accessReviews/definitions' -PageSize 100 }

Register-SocCollector -Name 'entitlement-management-catalogs' -Section 'Governance' -Transport 'Graph' `
    -Permission 'EntitlementManagement.Read.All' `
    -Description 'Entitlement management catalogs and whether they are enabled for external users.' `
    -Script { Invoke-SocGraphRequest -Path '/identityGovernance/entitlementManagement/catalogs' }

Register-SocCollector -Name 'entitlement-management-access-packages' -Section 'Governance' -Transport 'Graph' `
    -Permission 'EntitlementManagement.Read.All' `
    -Description 'Access packages available for self-service request.' `
    -Script { Invoke-SocGraphRequest -Path '/identityGovernance/entitlementManagement/accessPackages' -PageSize 100 }

Register-SocCollector -Name 'entitlement-management-assignment-policies' -Section 'Governance' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'EntitlementManagement.Read.All' `
    -Description 'Who may request each access package, which approvals apply, and the assignment lifetime.' `
    -Script { Invoke-SocGraphRequest -Path '/identityGovernance/entitlementManagement/assignmentPolicies' -PageSize 100 }

Register-SocCollector -Name 'terms-of-use-agreements' -Section 'Governance' -Transport 'Graph' `
    -Permission 'Agreement.Read.All' `
    -Description 'Terms of use agreements referenced by Conditional Access grant controls.' `
    -Script { Invoke-SocGraphRequest -Path '/identityGovernance/termsOfUse/agreements' }

Register-SocCollector -Name 'privileged-access-group-eligibility' -Section 'Governance' -Transport 'Graph' `
    -Permission 'PrivilegedAccess.Read.AzureADGroup' `
    -Description 'PIM for Groups eligibility schedules — membership or ownership of role-assignable groups that can be activated on demand.' `
    -Script { Invoke-SocGraphRequest -Path '/identityGovernance/privilegedAccess/group/eligibilitySchedules' -PageSize 100 }
