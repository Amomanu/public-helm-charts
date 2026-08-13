<#
    Applications.ps1 — app registrations, service principals and consent grants.

    This is where illicit consent grants and over-permissioned workload
    identities live, so it is collected at Standard depth despite the volume.
#>

Set-StrictMode -Version Latest

$script:SocApplicationSelect = @(
    'id', 'appId', 'displayName', 'createdDateTime', 'signInAudience', 'publisherDomain',
    'identifierUris', 'requiredResourceAccess', 'keyCredentials', 'passwordCredentials',
    'web', 'spa', 'publicClient', 'api', 'appRoles', 'isFallbackPublicClient', 'tags',
    'disabledByMicrosoftStatus', 'servicePrincipalLockConfiguration'
) -join ','

$script:SocServicePrincipalSelect = @(
    'id', 'appId', 'displayName', 'servicePrincipalType', 'accountEnabled', 'appOwnerOrganizationId',
    'signInAudience', 'tags', 'appRoles', 'oauth2PermissionScopes', 'keyCredentials',
    'passwordCredentials', 'replyUrls', 'homepage', 'preferredSingleSignOnMode',
    'disabledByMicrosoftStatus', 'appRoleAssignmentRequired', 'servicePrincipalNames'
) -join ','

function Get-SocServicePrincipalList {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    return Get-SocCached -Context $Context -Key 'servicePrincipals' -Factory {
        Invoke-SocGraphRequest -Path '/servicePrincipals' -Select $script:SocServicePrincipalSelect -PageSize 999
    }
}

function Get-SocApplicationList {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)

    return Get-SocCached -Context $Context -Key 'applications' -Factory {
        Invoke-SocGraphRequest -Path '/applications' -Select $script:SocApplicationSelect -PageSize 999
    }
}

Register-SocCollector -Name 'applications' -Section 'Applications' -Transport 'Graph' `
    -Permission 'Application.Read.All' `
    -Description 'App registrations with requested API permissions and credential metadata. Secret values are never returned by Graph.' `
    -Script {
    param($Context)
    Get-SocApplicationList -Context $Context
}

Register-SocCollector -Name 'service-principals' -Section 'Applications' -Transport 'Graph' `
    -Permission 'Application.Read.All' `
    -Description 'Enterprise applications and workload identities, including first-party and third-party principals.' `
    -Script {
    param($Context)
    Get-SocServicePrincipalList -Context $Context
}

Register-SocCollector -Name 'oauth2-permission-grants' -Section 'Applications' -Transport 'Graph' `
    -Permission 'Directory.Read.All' `
    -Description 'Delegated permission grants. Consent granted on behalf of all users, or unexpected mail/file scopes, is the signature of an illicit consent grant attack.' `
    -Script { Invoke-SocGraphRequest -Path '/oauth2PermissionGrants' -PageSize 999 }

Register-SocCollector -Name 'service-principal-app-role-assignments' -Section 'Applications' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'Application.Read.All' `
    -Description 'Application permissions granted to each service principal. One request per principal, so this runs at Extended depth only.' `
    -Script {
    param($Context)

    $principals = Get-SocServicePrincipalList -Context $Context
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($sp in $principals) {
        $id = Get-SocProperty $sp 'id'
        try {
            $assignments = Invoke-SocGraphRequest -Path "/servicePrincipals/$id/appRoleAssignments"
        }
        catch {
            continue
        }

        if (-not @($assignments).Count) { continue }

        $output.Add([pscustomobject]@{
                servicePrincipalId   = $id
                appId                = Get-SocProperty $sp 'appId'
                displayName          = Get-SocProperty $sp 'displayName'
                servicePrincipalType = Get-SocProperty $sp 'servicePrincipalType'
                appRoleAssignments   = $assignments
            })
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'credential-expiry' -Section 'Applications' -Transport 'Graph' `
    -Permission 'Application.Read.All' `
    -Description 'Flattened inventory of every application and service principal credential with its expiry state. Expired-but-present credentials and long-lived secrets are both worth review.' `
    -Script {
    param($Context)

    $now = (Get-Date).ToUniversalTime()
    $output = [System.Collections.Generic.List[object]]::new()

    function Add-SocCredentialRows {
        param($Owner, [string]$OwnerType, [string]$CredentialType, $Credentials)

        foreach ($credential in @($Credentials)) {
            $end = Get-SocProperty $credential 'endDateTime'
            $endUtc = $null
            $daysRemaining = $null

            if ($end) {
                $endUtc = ([datetime]$end).ToUniversalTime()
                $daysRemaining = [int]($endUtc - $now).TotalDays
            }

            $state = 'Unknown'
            if ($null -ne $daysRemaining) {
                $state = if ($daysRemaining -lt 0) { 'Expired' }
                elseif ($daysRemaining -le 30) { 'ExpiringWithin30Days' }
                elseif ($daysRemaining -le 90) { 'ExpiringWithin90Days' }
                else { 'Valid' }
            }

            $output.Add([pscustomobject]@{
                    ownerType      = $OwnerType
                    ownerId        = Get-SocProperty $Owner 'id'
                    appId          = Get-SocProperty $Owner 'appId'
                    displayName    = Get-SocProperty $Owner 'displayName'
                    credentialType = $CredentialType
                    keyId          = Get-SocProperty $credential 'keyId'
                    credentialName = Get-SocProperty $credential 'displayName'
                    startDateTime  = Get-SocProperty $credential 'startDateTime'
                    endDateTime    = $end
                    daysRemaining  = $daysRemaining
                    state          = $state
                })
        }
    }

    foreach ($app in (Get-SocApplicationList -Context $Context)) {
        Add-SocCredentialRows -Owner $app -OwnerType 'Application' -CredentialType 'Password' -Credentials (Get-SocProperty $app 'passwordCredentials')
        Add-SocCredentialRows -Owner $app -OwnerType 'Application' -CredentialType 'Certificate' -Credentials (Get-SocProperty $app 'keyCredentials')
    }

    foreach ($sp in (Get-SocServicePrincipalList -Context $Context)) {
        Add-SocCredentialRows -Owner $sp -OwnerType 'ServicePrincipal' -CredentialType 'Password' -Credentials (Get-SocProperty $sp 'passwordCredentials')
        Add-SocCredentialRows -Owner $sp -OwnerType 'ServicePrincipal' -CredentialType 'Certificate' -Credentials (Get-SocProperty $sp 'keyCredentials')
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'application-owners' -Section 'Applications' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'Application.Read.All' `
    -Description 'Owners of each app registration. An unexpected owner can add credentials to an app and inherit its permissions.' `
    -Script {
    param($Context)

    $applications = Get-SocApplicationList -Context $Context
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($app in $applications) {
        $id = Get-SocProperty $app 'id'
        try {
            $owners = Invoke-SocGraphRequest -Path "/applications/$id/owners" `
                -Select 'id,displayName,userPrincipalName'
        }
        catch {
            continue
        }

        if (-not @($owners).Count) { continue }

        $output.Add([pscustomobject]@{
                applicationId = $id
                appId         = Get-SocProperty $app 'appId'
                displayName   = Get-SocProperty $app 'displayName'
                owners        = $owners
            })
    }

    return $output.ToArray()
}
