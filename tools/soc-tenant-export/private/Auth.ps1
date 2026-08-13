<#
    Auth.ps1 — token acquisition for Microsoft Graph, Azure Resource Manager and
    the Microsoft Defender for Endpoint API.

    Client-credential and device-code flows are implemented directly against the
    identity platform so the common unattended path needs no PowerShell modules
    at all. Only -AuthMode ExistingSession depends on Az.Accounts, and only the
    Exchange/Purview collectors depend on ExchangeOnlineManagement.
#>

Set-StrictMode -Version Latest

# Well-known first-party public client, present in every tenant. Used only for
# the delegated device-code flow when the operator supplies no -ClientId.
$script:SocDefaultPublicClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'  # Microsoft Graph PowerShell

$script:SocEnvironments = @{
    Global   = @{
        Login    = 'https://login.microsoftonline.com'
        Graph    = 'https://graph.microsoft.com'
        Arm      = 'https://management.azure.com'
        Defender = 'https://api.securitycenter.microsoft.com'
        ExoEnv   = 'O365Default'
    }
    USGov    = @{
        Login    = 'https://login.microsoftonline.us'
        Graph    = 'https://graph.microsoft.us'
        Arm      = 'https://management.usgovcloudapi.net'
        Defender = 'https://api-gov.securitycenter.microsoft.us'
        ExoEnv   = 'O365USGovGCCHigh'
    }
    USGovDoD = @{
        Login    = 'https://login.microsoftonline.us'
        Graph    = 'https://dod-graph.microsoft.us'
        Arm      = 'https://management.usgovcloudapi.net'
        Defender = 'https://api-gov.securitycenter.microsoft.us'
        ExoEnv   = 'O365USGovDoD'
    }
    China    = @{
        Login    = 'https://login.chinacloudapi.cn'
        Graph    = 'https://microsoftgraph.chinacloudapi.cn'
        Arm      = 'https://management.chinacloudapi.cn'
        Defender = 'https://api.securitycenter.azure.cn'
        ExoEnv   = 'O365China'
    }
}

$script:SocAuth = $null

function Get-SocEndpoint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    return $script:SocEnvironments[$script:SocAuth.Environment][$Name]
}

function ConvertTo-SocBase64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Initialize-SocAuth {
    <#
        .SYNOPSIS
            Validates the requested auth mode and prepares shared token state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string]$AuthMode,
        [string]$ClientId,
        [securestring]$ClientSecret,
        [string]$CertificateThumbprint,
        [string]$CertificatePath,
        [securestring]$CertificatePassword
    )

    $certificate = $null

    switch ($AuthMode) {
        'ClientSecret' {
            if (-not $ClientId) { throw '-ClientId is required for -AuthMode ClientSecret.' }
            if (-not $ClientSecret) { throw '-ClientSecret is required for -AuthMode ClientSecret.' }
        }
        'Certificate' {
            if (-not $ClientId) { throw '-ClientId is required for -AuthMode Certificate.' }
            $certificate = Resolve-SocCertificate -Thumbprint $CertificateThumbprint -Path $CertificatePath -Password $CertificatePassword
        }
        'DeviceCode' {
            if (-not $ClientId) { $ClientId = $script:SocDefaultPublicClientId }
        }
        'ExistingSession' {
            if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
                throw '-AuthMode ExistingSession requires the Az.Accounts module and an active Connect-AzAccount session.'
            }
            Import-Module Az.Accounts -ErrorAction Stop
            if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
                throw 'No Azure PowerShell context found. Run Connect-AzAccount first, or use a different -AuthMode.'
            }
        }
    }

    $script:SocAuth = [pscustomobject]@{
        TenantId     = $TenantId
        Environment  = $Environment
        AuthMode     = $AuthMode
        ClientId     = $ClientId
        ClientSecret = $ClientSecret
        Certificate  = $certificate
        RefreshToken = $null
        Tokens       = @{}   # resource name -> @{ Token; ExpiresOn }
    }
}

function Resolve-SocCertificate {
    [CmdletBinding()]
    param([string]$Thumbprint, [string]$Path, [securestring]$Password)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Certificate file not found: $Path" }
        if ($Password) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                (Resolve-Path -LiteralPath $Path).ProviderPath, $Password,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        }
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Resolve-Path -LiteralPath $Path).ProviderPath)
    }

    if (-not $Thumbprint) {
        throw 'Provide -CertificateThumbprint (certificate store) or -CertificatePath (PFX file) for -AuthMode Certificate.'
    }

    $clean = $Thumbprint -replace '[^0-9A-Fa-f]', ''
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        if (-not (Test-Path $store)) { continue }
        $found = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $clean } | Select-Object -First 1
        if ($found) { return $found }
    }

    throw "Certificate with thumbprint '$Thumbprint' not found in CurrentUser\My or LocalMachine\My."
}

function New-SocClientAssertion {
    <#
        .SYNOPSIS
            Builds a signed JWT client assertion for certificate-based app-only auth.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TokenEndpoint)

    $cert = $script:SocAuth.Certificate
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw 'The supplied certificate has no accessible RSA private key.' }

    $now = [DateTimeOffset]::UtcNow

    $header = [ordered]@{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-SocBase64Url -Bytes $cert.GetCertHash()
    }
    $payload = [ordered]@{
        aud = $TokenEndpoint
        iss = $script:SocAuth.ClientId
        sub = $script:SocAuth.ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    }

    $encodedHeader = ConvertTo-SocBase64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json -Compress)))
    $encodedPayload = ConvertTo-SocBase64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)))
    $unsigned = "$encodedHeader.$encodedPayload"

    $signature = $rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    return "$unsigned." + (ConvertTo-SocBase64Url -Bytes $signature)
}

function Invoke-SocDeviceCodeFlow {
    <#
        .SYNOPSIS
            Runs the OAuth 2.0 device authorization grant and stores the refresh
            token so later resources can be obtained without re-prompting.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Scope)

    $login = Get-SocEndpoint -Name 'Login'
    $tenant = $script:SocAuth.TenantId

    $deviceResponse = Invoke-RestMethod -Method Post -Uri "$login/$tenant/oauth2/v2.0/devicecode" -Body @{
        client_id = $script:SocAuth.ClientId
        scope     = "$Scope offline_access"
    } -ErrorAction Stop

    Write-SocLog -Level Step -Message (Get-SocProperty $deviceResponse 'message' 'Complete sign-in in your browser.')

    $interval = [int](Get-SocProperty $deviceResponse 'interval' 5)
    $deadline = (Get-Date).AddSeconds([int](Get-SocProperty $deviceResponse 'expires_in' 900))

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            return Invoke-RestMethod -Method Post -Uri "$login/$tenant/oauth2/v2.0/token" -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $script:SocAuth.ClientId
                device_code = $deviceResponse.device_code
            } -ErrorAction Stop
        }
        catch {
            # if/else rather than switch: break/continue inside a switch nested in
            # a loop is ambiguous in PowerShell and does not reliably target the loop.
            $detail = Get-SocErrorDetail -ErrorRecord $_
            if ($detail.ServiceCode -eq 'authorization_pending') {
                # Expected until the operator finishes signing in — keep polling.
            }
            elseif ($detail.ServiceCode -eq 'slow_down') {
                $interval += 5
            }
            else {
                throw "Device code sign-in failed: $($detail.ServiceCode) $($detail.Message)"
            }
        }
    }

    throw 'Device code sign-in timed out.'
}

function Get-SocToken {
    <#
        .SYNOPSIS
            Returns a bearer token for the named resource, refreshing when the
            cached one is within five minutes of expiry.

        .PARAMETER Resource
            Graph, Arm or Defender.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Graph', 'Arm', 'Defender')][string]$Resource)

    if (-not $script:SocAuth) { throw 'Initialize-SocAuth has not been called.' }

    $cached = $script:SocAuth.Tokens[$Resource]
    if ($cached -and $cached.ExpiresOn -gt (Get-Date).AddMinutes(5)) {
        return $cached.Token
    }

    $audience = Get-SocEndpoint -Name $Resource
    $scope = "$audience/.default"
    $login = Get-SocEndpoint -Name 'Login'
    $tokenEndpoint = "$login/$($script:SocAuth.TenantId)/oauth2/v2.0/token"

    $response = $null

    switch ($script:SocAuth.AuthMode) {
        'ClientSecret' {
            $plain = [System.Net.NetworkCredential]::new('', $script:SocAuth.ClientSecret).Password
            $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                grant_type    = 'client_credentials'
                client_id     = $script:SocAuth.ClientId
                client_secret = $plain
                scope         = $scope
            } -ErrorAction Stop
        }
        'Certificate' {
            $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                grant_type            = 'client_credentials'
                client_id             = $script:SocAuth.ClientId
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion      = (New-SocClientAssertion -TokenEndpoint $tokenEndpoint)
                scope                 = $scope
            } -ErrorAction Stop
        }
        'DeviceCode' {
            if ($script:SocAuth.RefreshToken) {
                $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                    grant_type    = 'refresh_token'
                    client_id     = $script:SocAuth.ClientId
                    refresh_token = $script:SocAuth.RefreshToken
                    scope         = "$scope offline_access"
                } -ErrorAction Stop
            }
            else {
                $response = Invoke-SocDeviceCodeFlow -Scope $scope
            }
            $newRefresh = Get-SocProperty $response 'refresh_token'
            if ($newRefresh) { $script:SocAuth.RefreshToken = $newRefresh }
        }
        'ExistingSession' {
            $token = Get-SocTokenFromAzSession -Audience $audience
            $script:SocAuth.Tokens[$Resource] = @{ Token = $token; ExpiresOn = (Get-Date).AddMinutes(30) }
            return $token
        }
    }

    $accessToken = Get-SocProperty $response 'access_token'
    if (-not $accessToken) { throw "No access token returned for resource '$Resource'." }

    $expiresIn = [int](Get-SocProperty $response 'expires_in' 3600)
    $script:SocAuth.Tokens[$Resource] = @{
        Token     = $accessToken
        ExpiresOn = (Get-Date).AddSeconds($expiresIn)
    }

    return $accessToken
}

function Get-SocTokenFromAzSession {
    <#
        .SYNOPSIS
            Borrows a token from an existing Connect-AzAccount session.

        .DESCRIPTION
            Az.Accounts 5.x returns the token as a SecureString by default while
            earlier versions return plain text; both shapes are handled.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Audience)

    $result = Get-AzAccessToken -ResourceUrl $Audience -ErrorAction Stop
    $token = Get-SocProperty $result 'Token'

    if ($token -is [securestring]) {
        return [System.Net.NetworkCredential]::new('', $token).Password
    }
    return $token
}
