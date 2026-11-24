<#
.SYNOPSIS
    Tests proxy routing, port 443 reachability, and TLS certificate validity for CyberArk EPM regional URLs.

.PARAMETER Region
    CyberArk EPM tenant region: na, eu, ch, uk, it, au, br, ca, in, il, jp, sg, ae.

.PARAMETER TimeoutMs
    Timeout in milliseconds for TCP and HTTP requests. Defaults to 5000 ms.

.EXAMPLE
    .\Test-IdiraEpmConnectivity.ps1 -Region it
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('na', 'eu', 'ch', 'uk', 'it', 'au', 'br', 'ca', 'in', 'il', 'jp', 'sg', 'ae')]
    [string]$Region,

    [Parameter(Mandatory = $false)]
    [ValidateRange(500, 60000)]
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = 'Stop'

function Test-IdiraEpmConnectivity {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $parsed = $null
            if (-not [System.Uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -ne 'https') {
                throw "A valid HTTPS URI is required. Received: '$_'."
            }
            $true
        })]
        [string[]]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateRange(500, 60000)]
        [int]$TimeoutMs = 5000
    )

    begin {
        # Ensure TLS 1.2 is enabled in Windows PowerShell 5.1
        [System.Net.ServicePointManager]::SecurityProtocol = (
            [System.Net.ServicePointManager]::SecurityProtocol -bor
            [System.Net.SecurityProtocolType]::Tls12
        )
    }

    process {
        foreach ($rawUri in $Uri) {
            $targetUri = [System.Uri]::new($rawUri)

            # 1. Create request and inspect resolved system/PAC proxy
            $req = [System.Net.HttpWebRequest]::Create($targetUri)
            $req.Method = 'HEAD'
            $req.Timeout = $TimeoutMs
            $req.AllowAutoRedirect = $false

            $proxy = 'No'
            if ($null -ne $req.Proxy) {
                $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                if (-not $req.Proxy.IsBypassed($targetUri)) {
                    $proxyUri = $req.Proxy.GetProxy($targetUri)
                    if ($null -ne $proxyUri -and $proxyUri.AbsoluteUri -ne $targetUri.AbsoluteUri) {
                        $proxy = $proxyUri.AbsoluteUri
                    }
                }
            }

            # 2. Check direct TCP port 443 reachability
            $port443 = 'No'
            $tcp = [System.Net.Sockets.TcpClient]::new()
            try {
                if ($tcp.ConnectAsync($targetUri.Host, 443).Wait($TimeoutMs) -and $tcp.Connected) {
                    $port443 = 'Yes'
                }
            }
            catch { }
            finally {
                $tcp.Dispose()
            }

            # 3. Trigger TLS handshake and read ServicePoint.Certificate
            $tlsValid = $true
            $tlsError = $null
            $response = $null
            try {
                $response = $req.GetResponse()
            }
            catch [System.Net.WebException] {
                if ($null -ne $_.Exception.Response) {
                    # HTTP 403/404/405 still confirms the TLS handshake succeeded
                    $_.Exception.Response.Dispose()
                }
                else {
                    $tlsValid = $false
                    $tlsError = $_.Exception.Status
                }
            }
            catch {
                $tlsValid = $false
                $tlsError = $_.Exception.Message
            }
            finally {
                if ($null -ne $response) { $response.Dispose() }
            }

            # 4. Evaluate certificate metadata and validity
            $certSubject = 'N/A'
            $certIssuer  = 'N/A'
            $certExpire  = 'N/A'
            $certStatus  = 'Unreachable'

            if ($null -ne $req.ServicePoint.Certificate) {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($req.ServicePoint.Certificate)
                try {
                    $expiry = $cert.NotAfter
                    $today  = Get-Date

                    $certSubject = $cert.Subject
                    $certIssuer  = $cert.Issuer
                    $certExpire  = $expiry.ToString('yyyy-MM-dd HH:mm:ss')

                    if (-not $tlsValid) {
                        $certStatus = "Invalid ($tlsError)"
                    }
                    elseif ($expiry -lt $today) {
                        $certStatus = 'Expired'
                    }
                    elseif ($expiry -lt $today.AddDays(30)) {
                        $certStatus = 'Expiring (<30d)'
                        Write-Warning "Certificate for '$($targetUri.Host)' expires on $certExpire."
                    }
                    else {
                        $certStatus = 'Valid'
                    }
                }
                finally {
                    $cert.Dispose()
                }
            }

            [PSCustomObject]@{
                Hostname           = $targetUri.Host
                URI                = $targetUri.AbsoluteUri
                Proxy              = $proxy
                Port443            = $port443
                CertificateSubject = $certSubject
                CertificateIssuer  = $certIssuer
                CertificateExpire  = $certExpire
                CertificateStatus  = $certStatus
            }
        }
    }
}

# Build the 4 regional EPM URIs and stream them through the check
$r = $Region.ToLowerInvariant()

$s3Map = @{
    na = 'epm-downloads.s3.us-east-2.amazonaws.com'
    eu = 'epm-downloads-eu.s3.eu-central-1.amazonaws.com'
    ch = 'epm-downloads-ch.s3.eu-central-2.amazonaws.com'
    uk = 'epm-downloads-uk.s3.eu-west-2.amazonaws.com'
    it = 'epm-downloads-it.s3.eu-south-1.amazonaws.com'
    au = 'epm-downloads-au.s3.ap-southeast-2.amazonaws.com'
    br = 'epm-downloads-br.s3.sa-east-1.amazonaws.com'
    ca = 'epm-downloads-ca.s3.ca-central-1.amazonaws.com'
    in = 'epm-downloads-in.s3.ap-south-1.amazonaws.com'
    il = 'epm-downloads-il.s3.il-central-1.amazonaws.com'
    jp = 'epm-downloads-jp.s3.ap-northeast-1.amazonaws.com'
    sg = 'epm-downloads-sg.s3.ap-southeast-1.amazonaws.com'
    ae = 'epm-downloads-ae.s3.me-central-1.amazonaws.com'
}

@(
    "https://api-$r.epm.cyberark.cloud"
    "https://$($s3Map[$r])"
    "https://files-$r.epm.cyberark.com"
    "https://agents-$r.epm.cyberark.com"
) | Test-IdiraEpmConnectivity -TimeoutMs $TimeoutMs | Format-Table -AutoSize
