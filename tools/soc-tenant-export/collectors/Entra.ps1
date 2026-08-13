<#
    Entra.ps1 — Microsoft Entra ID tenant configuration.

    This is the core of the export: the identity controls a SOC reasons about
    when triaging an IAM ticket (Conditional Access, authentication methods,
    consent, federation, privileged roles).
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Tenant baseline
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'organization' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Organization.Read.All' `
    -Description 'Tenant profile, verified domains, technical contacts and directory-wide settings.' `
    -Script { Invoke-SocGraphRequest -Path '/organization' }

Register-SocCollector -Name 'subscribed-skus' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Organization.Read.All' `
    -Description 'Licensed SKUs and service plans. Determines which security features are actually available to the tenant.' `
    -Script { Invoke-SocGraphRequest -Path '/subscribedSkus' }

Register-SocCollector -Name 'security-defaults' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Security defaults enforcement state. Mutually exclusive with Conditional Access.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/identitySecurityDefaultsEnforcementPolicy' -Single }

Register-SocCollector -Name 'authorization-policy' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Default user role permissions, user consent settings, guest user role and self-service controls.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/authorizationPolicy' }

Register-SocCollector -Name 'directory-settings' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Directory.Read.All' `
    -Description 'Directory-level setting overrides, including custom banned password list and smart lockout thresholds.' `
    -Script { Invoke-SocGraphRequest -Path '/groupSettings' }

Register-SocCollector -Name 'domains' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Domain.Read.All' `
    -Description 'Registered domains with verification and authentication type. Federated domains change the trust model.' `
    -Script { Invoke-SocGraphRequest -Path '/domains' }

Register-SocCollector -Name 'domain-federation-configuration' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Domain.Read.All' `
    -Description 'Federation settings per federated domain — issuer URI, signing certificate and sign-in endpoints.' `
    -Script {
    param($Context)

    $domains = Invoke-SocGraphRequest -Path '/domains'
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($domain in $domains) {
        if ((Get-SocProperty $domain 'authenticationType') -ne 'Federated') { continue }

        $id = Get-SocProperty $domain 'id'
        try {
            $config = Invoke-SocGraphRequest -Path "/domains/$id/federationConfiguration"
            $output.Add([pscustomobject]@{ domainId = $id; federationConfiguration = $config })
        }
        catch {
            $output.Add([pscustomobject]@{
                    domainId                = $id
                    federationConfiguration = $null
                    error                   = (Get-SocErrorDetail -ErrorRecord $_).Message
                })
        }
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'certificate-based-auth-configuration' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Organization.Read.All' `
    -Description 'Certificate authorities trusted for certificate-based authentication.' `
    -Script {
    $orgs = Invoke-SocGraphRequest -Path '/organization' -Select 'id'
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($org in $orgs) {
        $id = Get-SocProperty $org 'id'
        $config = Invoke-SocGraphRequest -Path "/organization/$id/certificateBasedAuthConfiguration"
        foreach ($item in @($config)) { $output.Add($item) }
    }

    return $output.ToArray()
}

# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'conditional-access-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'All Conditional Access policies with conditions, grant and session controls, including report-only and disabled ones.' `
    -Script { Invoke-SocGraphRequest -Path '/identity/conditionalAccess/policies' }

Register-SocCollector -Name 'conditional-access-named-locations' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Named locations — IP ranges and country lists referenced by Conditional Access conditions.' `
    -Script { Invoke-SocGraphRequest -Path '/identity/conditionalAccess/namedLocations' }

Register-SocCollector -Name 'conditional-access-authentication-contexts' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Authentication context class references used for step-up authentication.' `
    -Script { Invoke-SocGraphRequest -Path '/identity/conditionalAccess/authenticationContextClassReferences' }

Register-SocCollector -Name 'authentication-strength-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.AuthenticationMethod' `
    -Description 'Built-in and custom authentication strengths and their allowed method combinations.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/authenticationStrengthPolicies' }

# ---------------------------------------------------------------------------
# Authentication methods and sign-in surface
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'authentication-methods-policy' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.AuthenticationMethod' `
    -Description 'Which authentication methods are enabled, for whom, and their per-method configuration.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/authenticationMethodsPolicy' -Single }

Register-SocCollector -Name 'authentication-method-configurations' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.AuthenticationMethod' `
    -Description 'Per-method configuration detail (FIDO2, Authenticator, SMS, voice, temporary access pass, certificate).' `
    -Script { Invoke-SocGraphRequest -Path '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations' }

Register-SocCollector -Name 'authentication-flows-policy' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Self-service sign-up flow settings for external users.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/authenticationFlowsPolicy' -Single }

Register-SocCollector -Name 'activity-based-timeout-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Idle session timeout policies for web applications.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/activityBasedTimeoutPolicies' }

Register-SocCollector -Name 'token-lifetime-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Custom token lifetime policies. Long-lived tokens extend the window after a session is stolen.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/tokenLifetimePolicies' }

Register-SocCollector -Name 'home-realm-discovery-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Home realm discovery policies. These can bypass the managed sign-in experience for federated users.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/homeRealmDiscoveryPolicies' }

Register-SocCollector -Name 'claims-mapping-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Custom claims mapping policies applied to application tokens.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/claimsMappingPolicies' }

Register-SocCollector -Name 'feature-rollout-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Directory.Read.All' `
    -Description 'Staged rollout policies for password hash sync and pass-through authentication.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/featureRolloutPolicies' -ApiVersion 'beta' }

# ---------------------------------------------------------------------------
# External access and consent
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'cross-tenant-access-default' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Default inbound/outbound B2B collaboration, B2B direct connect and trust settings for all external tenants.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/crossTenantAccessPolicy/default' -Single }

Register-SocCollector -Name 'cross-tenant-access-partners' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Per-partner cross-tenant access configuration, including MFA/device-claim trust overrides.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/crossTenantAccessPolicy/partners' }

Register-SocCollector -Name 'external-identities-policy' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Whether external users may self-service sign up and leave the tenant.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/externalIdentitiesPolicy' -ApiVersion 'beta' -Single }

Register-SocCollector -Name 'admin-consent-request-policy' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Admin consent workflow configuration and designated reviewers.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/adminConsentRequestPolicy' -Single }

Register-SocCollector -Name 'permission-grant-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.PermissionGrant' `
    -Description 'Permission grant policies that define which delegated permissions users may consent to themselves.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/permissionGrantPolicies' }

# ---------------------------------------------------------------------------
# Privileged access
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'directory-roles-with-members' -Section 'Entra' -Transport 'Graph' `
    -Permission 'RoleManagement.Read.Directory' `
    -Description 'Activated directory roles and their current members — the standing privilege inventory.' `
    -Script {
    $roles = Invoke-SocGraphRequest -Path '/directoryRoles'
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($role in $roles) {
        $id = Get-SocProperty $role 'id'
        $members = @()
        $memberError = $null

        try {
            $members = Invoke-SocGraphRequest -Path "/directoryRoles/$id/members"
        }
        catch {
            $memberError = (Get-SocErrorDetail -ErrorRecord $_).Message
        }

        $output.Add([pscustomobject]@{
                id             = $id
                displayName    = Get-SocProperty $role 'displayName'
                description    = Get-SocProperty $role 'description'
                roleTemplateId = Get-SocProperty $role 'roleTemplateId'
                memberCount    = @($members).Count
                members        = $members
                memberError    = $memberError
            })
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'role-definitions' -Section 'Entra' -Transport 'Graph' `
    -Permission 'RoleManagement.Read.Directory' `
    -Description 'Built-in and custom directory role definitions with their granted permissions.' `
    -Script { Invoke-SocGraphRequest -Path '/roleManagement/directory/roleDefinitions' }

Register-SocCollector -Name 'role-assignments' -Section 'Entra' -Transport 'Graph' `
    -Permission 'RoleManagement.Read.Directory' `
    -Description 'Active directory role assignments with principal and scope.' `
    -Script { Invoke-SocGraphRequest -Path '/roleManagement/directory/roleAssignments' -Expand 'principal' }

Register-SocCollector -Name 'pim-eligible-role-schedules' -Section 'Entra' -Transport 'Graph' `
    -Permission 'RoleManagement.Read.Directory' `
    -Description 'PIM eligible role assignments — privilege that can be activated on demand. Requires Entra ID P2.' `
    -Script { Invoke-SocGraphRequest -Path '/roleManagement/directory/roleEligibilitySchedules' -Expand 'principal,roleDefinition' }

Register-SocCollector -Name 'pim-active-role-schedules' -Section 'Entra' -Transport 'Graph' `
    -Permission 'RoleManagement.Read.Directory' `
    -Description 'PIM active role assignment schedules, including time-bound assignments. Requires Entra ID P2.' `
    -Script { Invoke-SocGraphRequest -Path '/roleManagement/directory/roleAssignmentSchedules' -Expand 'principal,roleDefinition' }

Register-SocCollector -Name 'pim-role-management-policies' -Section 'Entra' -Transport 'Graph' `
    -Permission 'RoleManagement.Read.Directory' `
    -Description 'PIM activation rules — MFA and justification requirements, approval, and maximum activation duration.' `
    -Script {
    $assignments = Invoke-SocGraphRequest -Path '/policies/roleManagementPolicyAssignments' `
        -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'"

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($assignment in $assignments) {
        $policyId = Get-SocProperty $assignment 'policyId'
        $rules = @()
        $ruleError = $null

        if ($policyId) {
            try {
                $rules = Invoke-SocGraphRequest -Path "/policies/roleManagementPolicies/$policyId/rules"
            }
            catch {
                $ruleError = (Get-SocErrorDetail -ErrorRecord $_).Message
            }
        }

        $output.Add([pscustomobject]@{
                policyId            = $policyId
                roleDefinitionId    = Get-SocProperty $assignment 'roleDefinitionId'
                scopeId             = Get-SocProperty $assignment 'scopeId'
                scopeType           = Get-SocProperty $assignment 'scopeType'
                rules               = $rules
                ruleError           = $ruleError
            })
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'administrative-units' -Section 'Entra' -Transport 'Graph' `
    -Permission 'AdministrativeUnit.Read.All' `
    -Description 'Administrative units used to scope delegated administration.' `
    -Script { Invoke-SocGraphRequest -Path '/directory/administrativeUnits' }

# ---------------------------------------------------------------------------
# Identity Protection and registration posture
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'authentication-method-registration-summary' -Section 'Entra' -Transport 'Graph' `
    -Permission 'AuditLog.Read.All' `
    -Description 'Tenant-wide counts of users registered for MFA, SSPR and passwordless. Requires Entra ID P1 or above.' `
    -Script { Invoke-SocGraphRequest -Path '/reports/authenticationMethods/usersRegisteredByFeature' -Single }

Register-SocCollector -Name 'user-registration-details' -Section 'Entra' -Transport 'Graph' `
    -Permission 'AuditLog.Read.All' -Depth 'Extended' `
    -Description 'Per-user MFA/SSPR registration state and default method. One row per user.' `
    -Script { Invoke-SocGraphRequest -Path '/reports/authenticationMethods/userRegistrationDetails' -PageSize 999 }

Register-SocCollector -Name 'risky-users-open' -Section 'Entra' -Transport 'Graph' `
    -Permission 'IdentityRiskyUser.Read.All' `
    -Description 'Users currently flagged at risk by Entra ID Protection. Current state rather than configuration. Requires Entra ID P2.' `
    -Script {
    Invoke-SocGraphRequest -Path '/identityProtection/riskyUsers' `
        -Filter "riskState ne 'remediated' and riskState ne 'dismissed'" -PageSize 500
}

Register-SocCollector -Name 'risky-service-principals' -Section 'Entra' -Transport 'Graph' `
    -Permission 'IdentityRiskyServicePrincipal.Read.All' `
    -Description 'Workload identities flagged at risk. Requires Workload Identities Premium.' `
    -Script {
    Invoke-SocGraphRequest -Path '/identityProtection/riskyServicePrincipals' `
        -Filter "riskState ne 'remediated' and riskState ne 'dismissed'" -PageSize 500
}

# ---------------------------------------------------------------------------
# Directory population (size-dependent — Extended only)
# ---------------------------------------------------------------------------

Register-SocCollector -Name 'guest-users' -Section 'Entra' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'User.Read.All' `
    -Description 'Guest accounts with creation type, sign-in activity and invitation state.' `
    -Script {
    Invoke-SocGraphRequest -Path '/users' -Filter "userType eq 'Guest'" -PageSize 999 `
        -Select 'id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,externalUserState,externalUserStateChangeDateTime,creationType,signInActivity'
}

Register-SocCollector -Name 'devices' -Section 'Entra' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'Device.Read.All' `
    -Description 'Registered and joined devices with trust type, compliance state and last activity.' `
    -Script {
    Invoke-SocGraphRequest -Path '/devices' -PageSize 999 `
        -Select 'id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime,profileType'
}
