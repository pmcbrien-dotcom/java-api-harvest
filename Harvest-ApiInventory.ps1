<#
.SYNOPSIS
    Discovers Java API services on the local machine and emits a normalized
    endpoint inventory enriched with framework, runtime, hosting and transport
    metadata.

.DESCRIPTION
    Java-only fleet discovery. Designed to be pushed to a server fleet over
    WinRM with Invoke-Command -FilePath and piped to Export-Csv by the caller.

    Discovery is sourced from authoritative places rather than access logs:
      - Tomcat server.xml connectors, web.xml servlet mappings, WAR contexts
      - Java process inspection across every listening TCP port
      - Spring Boot /actuator/mappings (including separate management ports)
      - Springfox /swagger-resources dynamic spec discovery
      - Live OpenAPI / Swagger spec download
      - On-disk spec files
      - Context paths from command line args and application.properties/yml

    Access logs are intentionally not parsed. Java frameworks expose the full
    route table through introspection, so logs are redundant, slower, and only
    reveal paths that happened to receive traffic in the lookback window.

    v5.3.0 adds -MaxRuntimeSec (hard stop, partial results still returned),
    -TaniumOutput (writes a compact pipe-delimited results file a Tanium
    sensor can read line by line) and a run-summary file alongside it.

    v5.2.0 restores everything v4.0.0 did that 5.x had dropped: probing
    loopback-bound listeners on 127.0.0.1, certificate bypass on PowerShell
    7, YAML spec parsing (live and on disk), Spring Boot 1.x flat actuator
    format, WebFlux dispatcherHandlers, patternsCondition, actuator noise
    skip list, context path from application.properties/yml beside the jar,
    on-disk spec scan beside the jar, Dropwizard admin port, every spec
    servers[]/schemes[] combination emitted with the host the spec declares,
    nested web.xml, Method='*' for servlet mappings, dedup across sources
    with a merged Sources column, UTF-8 CSV, and the -MaxSpecFiles,
    -SearchDepth and -DisableSpecScan safety controls.

    v5.1.0 widens process matching to procrun (tomcatN.exe/prunsrv.exe) and
    Tanuki wrapper.exe service hosts, skips AJP connectors, suppresses
    guessed candidates on Tomcat ports already covered by server.xml, probes
    the management port independently, harvests /actuator/mappings under
    Tomcat contexts, discovers Tomcat installs from running processes and
    CATALINA_* env vars, adds -ExcludePorts and automatic JMX/JDWP exclusion,
    caches JVM version lookups per executable, and records ProbeMs.

    v5.0.1 fixes read-only automatic variable collisions ($PID, $HOME),
    -not/-contains precedence guards, and bounds the HTTP body read.

    v5.0.0 adds a metadata layer on top of each discovered endpoint:
      - Framework identity, version and detection confidence
      - Java runtime version and vendor
      - Hosting Windows service and process owner
      - Listen address exposure (loopback vs all-interfaces vs specific NIC)
      - TLS handshake result, negotiated protocol and certificate expiry
      - Probe HTTP status and auth challenge presence
      - Application name and context path

.PARAMETER OutputCsv
    Optional path. When supplied the results are also written to CSV locally.
    Normally omitted for fleet runs, where the caller exports the returned
    objects instead.

.PARAMETER SafeProbeOnly
    Restrict all HTTP probing to HEAD requests. No GET bodies are retrieved,
    which means spec files are not downloaded and actuator mappings are not
    harvested. Use on sensitive production tiers.

.PARAMETER SkipTlsProbe
    Skip the TCP/SSL handshake used to classify a port as TLS and read the
    certificate. Saves roughly one second per discovered port.

.PARAMETER IncludeCommandLine
    Include the discovered Java process command line on each row. Always
    redacted for password, secret, token, key and credential style arguments,
    but still potentially sensitive. Off by default.

.PARAMETER ScanRoots
    Filesystem roots searched for Tomcat installations and on-disk specs.
    Defaults to the fixed local drives.

.PARAMETER ExcludePorts
    Listening ports to skip entirely. JMX remote ports and JDWP debug ports
    declared on the command line are excluded automatically; use this for
    cluster, Hazelcast, or other non-HTTP listeners the script cannot infer.

.PARAMETER HttpTimeoutSec
    Per-request timeout for HTTP probes. Default 5.

.PARAMETER MaxSpecFiles
    Maximum on-disk spec files parsed per search root. Default 10.

.PARAMETER SearchDepth
    Directory recursion depth for on-disk spec and web.xml searches. Default 5.

.PARAMETER DisableSpecScan
    Skip the on-disk spec file search entirely. Live spec download is
    unaffected.

.PARAMETER MaxRuntimeSec
    Hard stop. Discovery is abandoned after this many seconds and whatever
    was found so far is normalized and returned, with Status=Partial in the
    summary. Default 600. Zero disables the limit.

.PARAMETER TaniumOutput
    Directory for Tanium-friendly output. Writes results.txt (one compact
    pipe-delimited line per endpoint) and summary.txt (one key=value line
    per field) for a Tanium sensor to read. The directory is created if
    missing. The full CSV, when requested, is unaffected.

.PARAMETER DebugMode
    Verbose console output for single-host testing.

.EXAMPLE
    $results = Invoke-Command -ComputerName (Get-Content servers.txt) `
                              -FilePath .\Harvest-ApiInventory.ps1 `
                              -Credential $cred -ThrottleLimit 20
    $results | Export-Csv .\fleet_apis.csv -NoTypeInformation

.EXAMPLE
    .\Harvest-ApiInventory.ps1 -DebugMode -OutputCsv .\local.csv

.NOTES
    Version      : 5.3.0
    Requires     : Windows PowerShell 5.1 or PowerShell 7+ on Windows
    Side effects : None. Read-only. No config changes, no restarts, no agent
                   installs, no writes outside the script's own TEMP log.
    Encoding     : Pure 7-bit ASCII, no BOM. Do not introduce non-ASCII
                   characters - Windows PowerShell 5.1 will fail to parse.
#>

[CmdletBinding()]
param(
    [string]   $OutputCsv,
    [switch]   $SafeProbeOnly,
    [switch]   $SkipTlsProbe,
    [switch]   $IncludeCommandLine,
    [string[]] $ScanRoots,
    [int[]]    $ExcludePorts,
    [int]      $HttpTimeoutSec = 5,
    [int]      $MaxSpecFiles = 10,
    [int]      $SearchDepth = 5,
    [switch]   $DisableSpecScan,
    [int]      $MaxRuntimeSec = 600,
    [string]   $TaniumOutput,
    [switch]   $DebugMode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:ScriptVersion  = '5.3.0'
$script:ScanTimestamp  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$script:LogPath        = Join-Path $env:TEMP ('Harvest-ApiInventory_{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
$script:Mutex          = $null
$script:ProcessTable   = $null
$script:TcpListeners   = $null
$script:ServiceTable   = $null
$script:LocalFqdn      = $null
$script:Deadline       = $null
$script:TimedOut       = $false
$script:JavaInfoCache  = @{}
$script:TomcatPorts    = @{}
$script:AuxPortsDone   = @{}

# Paths probed on a Java port when nothing better is available. These are
# candidates, not discoveries - rows sourced from here are marked as such.
$script:FallbackPaths = @(
    '/health', '/status', '/info',
    '/swagger', '/swagger-ui.html', '/swagger-resources',
    '/v2/api-docs', '/v3/api-docs', '/openapi.json', '/openapi.yaml',
    '/actuator', '/actuator/health', '/actuator/mappings',
    '/q/health', '/q/openapi'
)

# Spec locations worth a direct fetch once a framework is known.
$script:SpecPathsByFramework = @{
    'SpringBoot' = @('/v3/api-docs', '/v3/api-docs.yaml', '/v2/api-docs', '/openapi.json')
    'Quarkus'    = @('/q/openapi', '/openapi')
    'Micronaut'  = @('/swagger/views/swagger-ui', '/swagger.yml', '/openapi.json')
    'Dropwizard' = @('/swagger.json', '/openapi.json', '/openapi.yaml')
    'Jetty'      = @('/openapi.json', '/swagger.json')
    'Tomcat'     = @('/v3/api-docs', '/openapi.json', '/swagger.json')
    'Unknown'    = @('/v3/api-docs', '/v2/api-docs', '/openapi.json', '/openapi.yaml', '/swagger.json', '/openapi', '/swagger/v1/swagger.json')
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string] $Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue } catch { }
    if ($DebugMode) {
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
            default { Write-Host $line }
        }
    }
}

# ---------------------------------------------------------------------------
# Runtime budget
# ---------------------------------------------------------------------------

function Test-OutOfTime {
    if ($null -eq $script:Deadline) { return $false }
    if ($script:TimedOut) { return $true }
    if ((Get-Date) -gt $script:Deadline) {
        $script:TimedOut = $true
        Write-Log ('MaxRuntimeSec reached; returning partial results') 'WARN'
        return $true
    }
    return $false
}

# ---------------------------------------------------------------------------
# Single instance guard
# ---------------------------------------------------------------------------

function Enter-SingleInstance {
    try {
        $created = $false
        $script:Mutex = New-Object System.Threading.Mutex($true, 'Global\Harvest-ApiInventory', [ref]$created)
        if (-not $created) {
            $got = $script:Mutex.WaitOne(0)
            if (-not $got) {
                Write-Log 'Another instance is already running. Exiting.' 'WARN'
                return $false
            }
        }
        return $true
    }
    catch {
        Write-Log ('Mutex acquisition failed, continuing anyway: {0}' -f $_.Exception.Message) 'WARN'
        return $true
    }
}

function Exit-SingleInstance {
    if ($null -ne $script:Mutex) {
        try { $script:Mutex.ReleaseMutex() } catch { }
        try { $script:Mutex.Dispose() }      catch { }
    }
}

# ---------------------------------------------------------------------------
# TLS initialization for outbound probes
# ---------------------------------------------------------------------------

function Initialize-Tls {
    try {
        $desired = 0
        foreach ($name in @('Tls12', 'Tls13')) {
            if ([enum]::GetNames([Net.SecurityProtocolType]) -contains $name) {
                $desired = $desired -bor [Net.SecurityProtocolType]::$name
            }
        }
        if ($desired -ne 0) { [Net.ServicePointManager]::SecurityProtocol = $desired }
    }
    catch {
        Write-Log ('Could not set SecurityProtocol: {0}' -f $_.Exception.Message) 'WARN'
    }

    # Internal endpoints routinely present self-signed or internal-CA certs.
    # Probing is read-only, so validation is bypassed for the scan session only.
    # ServerCertificateValidationCallback is honored by HttpWebRequest on both
    # .NET Framework and .NET Core; the ICertificatePolicy below is a belt-and-
    # braces fallback for Windows PowerShell.
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) $true }
    }
    catch {
        Write-Log ('ServerCertificateValidationCallback unavailable: {0}' -f $_.Exception.Message) 'WARN'
    }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        try {
            if (-not ('HarvestCertPolicy' -as [type])) {
                Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class HarvestCertPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
                                      WebRequest req, int problem) { return true; }
}
'@ -ErrorAction Stop
            }
            [Net.ServicePointManager]::CertificatePolicy = New-Object HarvestCertPolicy
        }
        catch {
            Write-Log ('Certificate policy bypass unavailable: {0}' -f $_.Exception.Message) 'WARN'
        }
    }
}

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

function Invoke-HttpProbe {
    <#
        Returns a hashtable: Success, StatusCode, Headers, Content, Error.
        Never throws. Honors -SafeProbeOnly by downgrading GET to HEAD.
    #>
    param(
        [string] $Uri,
        [ValidateSet('GET', 'HEAD')]
        [string] $Method = 'GET'
    )

    if ($SafeProbeOnly) { $Method = 'HEAD' }

    $result = @{
        Success    = $false
        StatusCode = $null
        Headers    = @{}
        Content    = $null
        Error      = $null
    }

    try {
        $req = [Net.WebRequest]::Create($Uri)
        $req.Method                        = $Method
        $req.Timeout                       = $HttpTimeoutSec * 1000
        $req.ReadWriteTimeout              = $HttpTimeoutSec * 1000
        $req.AllowAutoRedirect             = $false
        $req.UserAgent                     = 'Harvest-ApiInventory/' + $script:ScriptVersion
        if ($req -is [Net.HttpWebRequest]) {
            $req.ServicePoint.ConnectionLeaseTimeout = $HttpTimeoutSec * 1000
            $req.KeepAlive                 = $false
        }

        $resp = $req.GetResponse()
        $result.Success    = $true
        $result.StatusCode = [int]$resp.StatusCode

        foreach ($h in $resp.Headers.AllKeys) { $result.Headers[$h] = $resp.Headers[$h] }

        if ($Method -eq 'GET') {
            $stream = $resp.GetResponseStream()
            $reader = New-Object IO.StreamReader($stream)
            # Bounded read. Some spec files are very large and we only need
            # enough to parse structure. 4 MB cap, 64 KB chunks.
            $sb       = New-Object Text.StringBuilder
            $chunk    = New-Object char[] 65536
            $maxChars = 4194304
            while ($sb.Length -lt $maxChars) {
                $n = $reader.Read($chunk, 0, $chunk.Length)
                if ($n -le 0) { break }
                [void]$sb.Append($chunk, 0, $n)
            }
            if ($sb.Length -gt 0) { $result.Content = $sb.ToString() }
            $reader.Close()
            $stream.Close()
        }
        $resp.Close()
    }
    catch [Net.WebException] {
        $result.Error = $_.Exception.Message
        $resp = $_.Exception.Response
        if ($null -ne $resp) {
            try {
                $result.StatusCode = [int]$resp.StatusCode
                foreach ($h in $resp.Headers.AllKeys) { $result.Headers[$h] = $resp.Headers[$h] }
                # A 401/403 still proves the endpoint exists and is protected.
                $result.Success = $true
                $resp.Close()
            } catch { }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-ProbeHost {
    <#
        A listener bound only to loopback cannot be reached through the FQDN.
        Probe such ports on 127.0.0.1 (or ::1); the record still carries the
        FQDN as its Host so the inventory stays fleet-addressable.
    #>
    param([string] $Fqdn, [string] $Exposure, [string[]] $Addresses)
    if ($Exposure -eq 'Loopback') {
        if ($Addresses -contains '::1' -and -not ($Addresses | Where-Object { $_ -match '^127\.' })) { return '[::1]' }
        return '127.0.0.1'
    }
    return $Fqdn
}

function Get-HeaderValue {
    param([hashtable] $Headers, [string] $Name)
    if ($null -eq $Headers) { return $null }
    foreach ($k in $Headers.Keys) {
        if ($k -and $k.ToLower() -eq $Name.ToLower()) { return $Headers[$k] }
    }
    return $null
}

# ---------------------------------------------------------------------------
# TLS endpoint probe
# ---------------------------------------------------------------------------

function Test-TlsEndpoint {
    <#
        Performs a raw TCP connect plus SSL handshake to decide whether a port
        is TLS, what protocol was negotiated, and when the cert expires.
        Returns a hashtable; never throws.
    #>
    param([string] $TargetHost, [int] $Port)

    $out = @{
        TlsEnabled   = $false
        TlsProtocol  = $null
        CertSubject  = $null
        CertNotAfter = $null
        CertIssuer   = $null
    }
    if ($SkipTlsProbe) { return $out }

    $client = $null
    $ssl    = $null
    try {
        $client = New-Object Net.Sockets.TcpClient
        $iar    = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($HttpTimeoutSec * 1000, $false)) {
            return $out
        }
        $client.EndConnect($iar)

        $validator = [Net.Security.RemoteCertificateValidationCallback] { param($a, $b, $c, $d) return $true }
        $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false, $validator)
        $ssl.AuthenticateAsClient($TargetHost)

        $out.TlsEnabled  = $true
        $out.TlsProtocol = $ssl.SslProtocol.ToString()

        $cert = $ssl.RemoteCertificate
        if ($null -ne $cert) {
            $x509 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert)
            $out.CertSubject  = $x509.Subject
            $out.CertIssuer   = $x509.Issuer
            $out.CertNotAfter = $x509.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
        }
    }
    catch {
        # Not TLS, or handshake refused. Either way it is a plaintext port.
    }
    finally {
        if ($null -ne $ssl)    { try { $ssl.Dispose() }    catch { } }
        if ($null -ne $client) { try { $client.Close() }   catch { } }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Cached system inventory
# ---------------------------------------------------------------------------

function Get-CachedProcessTable {
    if ($null -ne $script:ProcessTable) { return $script:ProcessTable }
    $table = @{}
    try {
        # java.exe / javaw.exe for plain JVMs; tomcatN.exe and prunsrv.exe
        # for Apache procrun service hosts; wrapper.exe for Tanuki Java
        # Service Wrapper. Most production Tomcats on Windows run as procrun
        # services and never show up as java.exe.
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                 Where-Object { $_.Name -match '^(javaw?|tomcat\d*|prunsrv|wrapper)\.exe$' }
        foreach ($p in $procs) {
            $owner = $null
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($o -and $o.User) {
                    $owner = if ($o.Domain) { '{0}\{1}' -f $o.Domain, $o.User } else { $o.User }
                }
            } catch { }

            $start = $null
            try { if ($p.CreationDate) { $start = ([datetime]$p.CreationDate).ToString('yyyy-MM-dd HH:mm:ss') } } catch { }

            $table[[int]$p.ProcessId] = [pscustomobject]@{
                ProcessId   = [int]$p.ProcessId
                Name        = $p.Name
                ExePath     = $p.ExecutablePath
                CommandLine = $p.CommandLine
                Owner       = $owner
                StartTime   = $start
            }
        }
    }
    catch {
        Write-Log ('Win32_Process query failed: {0}' -f $_.Exception.Message) 'ERROR'
    }
    $script:ProcessTable = $table
    Write-Log ('Cached {0} Java process(es)' -f $table.Count) 'DEBUG'
    return $script:ProcessTable
}

function Get-CachedTcpListeners {
    if ($null -ne $script:TcpListeners) { return $script:TcpListeners }
    $listeners = @()
    try {
        $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop
        foreach ($c in $conns) {
            $listeners += [pscustomobject]@{
                Port          = [int]$c.LocalPort
                LocalAddress  = $c.LocalAddress
                ProcessId     = [int]$c.OwningProcess
            }
        }
    }
    catch {
        # Fallback for hosts without the NetTCPIP module.
        try {
            $netstat = netstat -ano -p TCP 2>$null
            foreach ($line in $netstat) {
                if ($line -match 'LISTENING' -and $line -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)') {
                    $listeners += [pscustomobject]@{
                        Port         = [int]$Matches[2]
                        LocalAddress = $Matches[1].Trim('[', ']')
                        ProcessId    = [int]$Matches[3]
                    }
                }
            }
        }
        catch {
            Write-Log ('TCP listener enumeration failed: {0}' -f $_.Exception.Message) 'ERROR'
        }
    }
    $script:TcpListeners = $listeners
    Write-Log ('Cached {0} listening TCP port(s)' -f $listeners.Count) 'DEBUG'
    return $script:TcpListeners
}

function Get-CachedServiceTable {
    if ($null -ne $script:ServiceTable) { return $script:ServiceTable }
    $table = @{}
    try {
        $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
                Where-Object { $_.ProcessId -and $_.ProcessId -ne 0 }
        foreach ($s in $svcs) {
            if (-not $table.ContainsKey([int]$s.ProcessId)) {
                $table[[int]$s.ProcessId] = [pscustomobject]@{
                    ServiceName = $s.Name
                    DisplayName = $s.DisplayName
                    StartMode   = $s.StartMode
                    ServiceUser = $s.StartName
                }
            }
        }
    }
    catch {
        Write-Log ('Win32_Service query failed: {0}' -f $_.Exception.Message) 'WARN'
    }
    $script:ServiceTable = $table
    return $script:ServiceTable
}

function Get-LocalFqdn {
    if ($null -ne $script:LocalFqdn) { return $script:LocalFqdn }
    $name = $null

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.Domain -and $cs.Domain -notmatch '^(WORKGROUP|MSHOME)$') {
            $name = '{0}.{1}' -f $cs.Name.ToLower(), $cs.Domain.ToLower()
        }
    } catch { }

    if (-not $name) {
        try {
            $props = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
            if ($props.DomainName) {
                $name = '{0}.{1}' -f $props.HostName.ToLower(), $props.DomainName.ToLower()
            }
        } catch { }
    }

    if (-not $name) {
        try {
            $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                   Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
                   Select-Object -First 1).IPAddress
            if ($ip) {
                $entry = [Net.Dns]::GetHostEntry($ip)
                if ($entry -and $entry.HostName) { $name = $entry.HostName.ToLower() }
            }
        } catch { }
    }

    if (-not $name) { $name = $env:COMPUTERNAME.ToLower() }
    $script:LocalFqdn = $name
    return $script:LocalFqdn
}

# ---------------------------------------------------------------------------
# Command line handling
# ---------------------------------------------------------------------------

function Protect-CommandLine {
    <#
        Redacts credential-bearing arguments before anything is emitted.
        Applied unconditionally wherever a command line leaves this script.
    #>
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }

    $patterns = @(
        '(?i)(-D[\w\.]*(?:password|passwd|pwd)[\w\.]*=)([^\s"]+)',
        '(?i)(-D[\w\.]*(?:secret|token|apikey|api_key|accesskey)[\w\.]*=)([^\s"]+)',
        '(?i)(-D[\w\.]*(?:credential|keystorepass|truststorepass)[\w\.]*=)([^\s"]+)',
        '(?i)(--(?:password|token|secret|api-key)[= ])([^\s"]+)'
    )
    $out = $CommandLine
    foreach ($p in $patterns) { $out = [regex]::Replace($out, $p, '$1[REDACTED]') }
    return $out
}

function Get-AppNameFromCommandLine {
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }
    if ($CommandLine -match '(?i)-Dspring\.application\.name=([^\s"]+)') { return $Matches[1] }
    if ($CommandLine -match '(?i)-Dquarkus\.application\.name=([^\s"]+)') { return $Matches[1] }
    if ($CommandLine -match '(?i)-Dmicronaut\.application\.name=([^\s"]+)') { return $Matches[1] }
    # Fall back to the executed jar's base name.
    if ($CommandLine -match '(?i)-jar\s+"?([^\s"]+\.jar)"?') {
        return [IO.Path]::GetFileNameWithoutExtension($Matches[1])
    }
    return $null
}

function Get-ContextPathFromCommandLine {
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }
    foreach ($pattern in @(
        '(?i)-Dserver\.servlet\.context-path=([^\s"]+)',
        '(?i)-Dserver\.context-path=([^\s"]+)',
        '(?i)-Dquarkus\.http\.root-path=([^\s"]+)',
        '(?i)-Dmicronaut\.server\.context-path=([^\s"]+)',
        '(?i)--server\.servlet\.context-path=([^\s"]+)'
    )) {
        if ($CommandLine -match $pattern) { return $Matches[1] }
    }
    return $null
}

function Get-NonHttpPortsFromCommandLine {
    <#
        Ports declared on the command line that are known not to be HTTP:
        JMX remote (and its RMI registry) and the JDWP debug agent.
    #>
    param([string] $CommandLine)
    $ports = @()
    if (-not $CommandLine) { return $ports }
    foreach ($m in [regex]::Matches($CommandLine, '(?i)-Dcom\.sun\.management\.jmxremote\.(?:rmi\.)?port=(\d+)')) {
        $ports += [int]$m.Groups[1].Value
    }
    if ($CommandLine -match '(?i)-agentlib:jdwp=[^\s"]*address=(?:[\w\.\*]+:)?(\d+)') { $ports += [int]$Matches[1] }
    if ($CommandLine -match '(?i)-Xrunjdwp:[^\s"]*address=(?:[\w\.\*]+:)?(\d+)')     { $ports += [int]$Matches[1] }
    return $ports
}

function Get-CatalinaBaseFromCommandLine {
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }
    if ($CommandLine -match '(?i)-Dcatalina\.base="?([^\s"]+)"?') { return $Matches[1].TrimEnd('\\') }
    if ($CommandLine -match '(?i)-Dcatalina\.home="?([^\s"]+)"?') { return $Matches[1].TrimEnd('\\') }
    return $null
}

function Get-JarDirectoryFromCommandLine {
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }
    if ($CommandLine -match '(?i)-jar\s+"?([^\s"]+\.(?:jar|war))"?' -or
        $CommandLine -match '(?i)(?:^|\s)"?([A-Za-z]:\\[^\s"]+\.(?:jar|war))"?') {
        try { return (Split-Path $Matches[1] -Parent) } catch { }
    }
    return $null
}

function Get-ContextPathFromConfig {
    <#
        Spring Boot reads application.properties / application.yml from the
        working directory and a config/ subdirectory beside the jar.
    #>
    param([string] $WorkDir)
    if (-not $WorkDir -or -not (Test-Path $WorkDir)) { return $null }

    foreach ($rel in @('application.properties', 'config\application.properties')) {
        $f = Join-Path $WorkDir $rel
        if (-not (Test-Path $f)) { continue }
        try {
            $content = Get-Content $f -Raw -ErrorAction Stop
            if ($content -match '(?m)^\s*server\.servlet\.context-path\s*=\s*(\S+)') { return $Matches[1].TrimEnd('/') }
            if ($content -match '(?m)^\s*server\.context-path\s*=\s*(\S+)')         { return $Matches[1].TrimEnd('/') }
        } catch { }
    }
    foreach ($rel in @('application.yml', 'application.yaml', 'config\application.yml', 'config\application.yaml')) {
        $f = Join-Path $WorkDir $rel
        if (-not (Test-Path $f)) { continue }
        try {
            $content = Get-Content $f -Raw -ErrorAction Stop
            if ($content -match '(?m)^\s*context-path\s*:\s*[''"]?([^\s''"#]+)') { return $Matches[1].TrimEnd('/') }
        } catch { }
    }
    return $null
}

function Get-DropwizardAdminPortFromCommandLine {
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }
    if ($CommandLine -match '(?i)-Ddw\.server\.adminConnectors\[0\]\.port=(\d+)') { return [int]$Matches[1] }
    return $null
}

function Get-ManagementPortFromCommandLine {
    param([string] $CommandLine)
    if (-not $CommandLine) { return $null }
    if ($CommandLine -match '(?i)-Dmanagement\.server\.port=(\d+)') { return [int]$Matches[1] }
    if ($CommandLine -match '(?i)--management\.server\.port=(\d+)') { return [int]$Matches[1] }
    return $null
}

# ---------------------------------------------------------------------------
# Java runtime identification
# ---------------------------------------------------------------------------

function Get-JavaRuntimeInfo {
    <#
        Reads the JDK 'release' file next to java.exe rather than launching a
        JVM. Falls back to 'java -version' with a guarded ErrorActionPreference
        because java writes its version banner to stderr.
    #>
    param([string] $ExePath, [string] $CommandLine)

    $info = @{ JavaVersion = $null; JavaVendor = $null }

    # procrun and wrapper hosts are not the JVM. Their command line or
    # registry config names the jvm.dll; derive the JDK home from that.
    if ($ExePath -and $ExePath -match '(?i)(tomcat\d*|prunsrv|wrapper)\.exe$') {
        if ($CommandLine -and $CommandLine -match '(?i)(?:--Jvm=|-Djava\.home=|wrapper\.java\.command=)"?([^\s"]+)') {
            $candidate = $Matches[1]
            if ($candidate -match '(?i)jvm\.dll$') {
                # <jdk>\bin\server\jvm.dll -> <jdk>\bin\java.exe
                $ExePath = Join-Path (Split-Path (Split-Path $candidate -Parent) -Parent) 'java.exe'
            }
            elseif ($candidate -match '(?i)java(w)?\.exe$') { $ExePath = $candidate }
            else { $ExePath = Join-Path $candidate 'bin\java.exe' }
        }
        else {
            $ExePath = $null
        }
    }
    if (-not $ExePath) { return $info }

    $cacheKey = $ExePath.ToLower()
    if ($script:JavaInfoCache.ContainsKey($cacheKey)) { return $script:JavaInfoCache[$cacheKey] }

    try {
        $binDir  = Split-Path $ExePath -Parent
        $homeDir = Split-Path $binDir  -Parent
        $release = Join-Path $homeDir 'release'
        if (Test-Path $release) {
            foreach ($line in (Get-Content $release -ErrorAction SilentlyContinue)) {
                if ($line -match '^JAVA_VERSION="?([^"]+)"?') { $info.JavaVersion = $Matches[1] }
                if ($line -match '^IMPLEMENTOR="?([^"]+)"?')  { $info.JavaVendor  = $Matches[1] }
            }
            if ($info.JavaVersion) { $script:JavaInfoCache[$cacheKey] = $info; return $info }
        }
    } catch { }

    if (-not (Test-Path $ExePath)) { $script:JavaInfoCache[$cacheKey] = $info; return $info }

    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = & $ExePath -version 2>&1
        $ErrorActionPreference = $prev
        $text = ($out | Out-String)
        if ($text -match '(?i)version\s+"([^"]+)"') { $info.JavaVersion = $Matches[1] }
        if ($text -match '(?i)(OpenJDK|Java\(TM\)|Temurin|Zulu|Corretto|GraalVM|IBM)') {
            $info.JavaVendor = $Matches[1]
        }
    } catch { }

    $script:JavaInfoCache[$cacheKey] = $info
    return $info
}

# ---------------------------------------------------------------------------
# Framework identification
# ---------------------------------------------------------------------------

function Resolve-FrameworkFromCommandLine {
    <#
        Static identification from the process command line and classpath.
        Returns Framework, Version and Evidence. Confidence is 'Inferred'
        because nothing has been confirmed over the wire yet.
    #>
    param([string] $CommandLine)

    $result = @{ Framework = 'Unknown'; Version = $null; Evidence = $null }
    if (-not $CommandLine) { return $result }

    $signatures = @(
        @{ F = 'SpringBoot'; P = 'org\.springframework\.boot\.loader' },
        @{ F = 'SpringBoot'; P = 'spring-boot-\d' },
        @{ F = 'SpringBoot'; P = 'spring-boot\.jar|spring-boot-starter' },
        @{ F = 'Quarkus';    P = 'io\.quarkus|quarkus-run\.jar|quarkus-application' },
        @{ F = 'Micronaut';  P = 'io\.micronaut|micronaut-\d|micronaut-core' },
        @{ F = 'Tomcat';     P = 'org\.apache\.catalina\.startup\.Bootstrap|catalina\.(base|home)|\\tomcat\d*\.exe' },
        @{ F = 'Jetty';      P = 'org\.eclipse\.jetty|jetty-runner|jetty\.(base|home)' },
        @{ F = 'Undertow';   P = 'io\.undertow' },
        @{ F = 'Dropwizard'; P = 'io\.dropwizard' },
        @{ F = 'Vertx';      P = 'io\.vertx' },
        @{ F = 'Play';       P = 'play\.core\.server|play\.runsupport' },
        @{ F = 'Javalin';    P = 'io\.javalin' },
        @{ F = 'Ratpack';    P = 'ratpack\.' },
        @{ F = 'Spark';      P = 'spark\.Spark|sparkjava' },
        @{ F = 'WildFly';    P = 'jboss-modules|org\.jboss\.as' },
        @{ F = 'WebLogic';   P = 'weblogic\.Server' },
        @{ F = 'WebSphere';  P = 'com\.ibm\.ws\.' }
    )

    foreach ($sig in $signatures) {
        if ($CommandLine -match $sig.P) {
            $result.Framework = $sig.F
            $result.Evidence  = 'CommandLine match: ' + $sig.P
            break
        }
    }

    # Version from a jar name on the classpath, where one is present.
    switch ($result.Framework) {
        'SpringBoot' { if ($CommandLine -match 'spring-boot[\w-]*-(\d+\.\d+\.\d+[\w\.-]*)\.jar') { $result.Version = $Matches[1] } }
        'Quarkus'    { if ($CommandLine -match 'quarkus[\w-]*-(\d+\.\d+\.\d+[\w\.-]*)\.jar')     { $result.Version = $Matches[1] } }
        'Micronaut'  { if ($CommandLine -match 'micronaut[\w-]*-(\d+\.\d+\.\d+[\w\.-]*)\.jar')   { $result.Version = $Matches[1] } }
        'Jetty'      { if ($CommandLine -match 'jetty[\w-]*-(\d+\.\d+\.\d+[\w\.-]*)\.jar')       { $result.Version = $Matches[1] } }
        default      { }
    }

    return $result
}

function Resolve-FrameworkFromJarManifest {
    <#
        Reads META-INF/MANIFEST.MF out of the executed jar. This is the
        strongest static signal available - Spring Boot stamps its own version
        there, and Implementation-Title names the application.
    #>
    param([string] $CommandLine)

    $result = @{ Framework = $null; Version = $null; AppName = $null; Evidence = $null }
    if (-not $CommandLine) { return $result }
    if ($CommandLine -notmatch '(?i)-jar\s+"?([^\s"]+\.jar)"?') { return $result }

    $jar = $Matches[1]
    if (-not (Test-Path $jar)) { return $result }

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [IO.Compression.ZipFile]::OpenRead($jar)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | Select-Object -First 1
            if ($null -ne $entry) {
                $reader   = New-Object IO.StreamReader($entry.Open())
                $manifest = $reader.ReadToEnd()
                $reader.Close()

                if ($manifest -match '(?m)^Spring-Boot-Version:\s*(\S+)') {
                    $result.Framework = 'SpringBoot'
                    $result.Version   = $Matches[1]
                    $result.Evidence  = 'MANIFEST.MF Spring-Boot-Version'
                }
                elseif ($manifest -match '(?m)^Implementation-Title:\s*(.+)$') {
                    $title = $Matches[1].Trim()
                    if ($title -match '(?i)quarkus')   { $result.Framework = 'Quarkus' }
                    if ($title -match '(?i)micronaut') { $result.Framework = 'Micronaut' }
                    if ($result.Framework) { $result.Evidence = 'MANIFEST.MF Implementation-Title' }
                }

                if ($manifest -match '(?m)^Implementation-Title:\s*(.+)$') { $result.AppName = $Matches[1].Trim() }
                if (-not $result.Version -and $manifest -match '(?m)^Implementation-Version:\s*(\S+)') {
                    $result.Version = $Matches[1]
                }
            }
        }
        finally { $zip.Dispose() }
    }
    catch {
        Write-Log ('Manifest read failed for {0}: {1}' -f $jar, $_.Exception.Message) 'DEBUG'
    }

    return $result
}

function Resolve-FrameworkFromProbe {
    <#
        Wire-level confirmation. A framework identified here is 'Confirmed'
        because the running process answered for itself.
    #>
    param([string] $BaseUrl)

    $result = @{ Framework = $null; Version = $null; Evidence = $null; ServerHeader = $null }

    # Server / X-Powered-By headers on the root.
    $root = Invoke-HttpProbe -Uri $BaseUrl -Method 'HEAD'
    if ($root.Success) {
        $server = Get-HeaderValue $root.Headers 'Server'
        $xpb    = Get-HeaderValue $root.Headers 'X-Powered-By'
        $result.ServerHeader = $server

        if ($server) {
            if ($server -match '(?i)jetty\(?([\d\.]+)?') {
                $result.Framework = 'Jetty'
                if ($Matches.Count -gt 1 -and $Matches[1]) { $result.Version = $Matches[1] }
                $result.Evidence = 'Server header'
            }
            elseif ($server -match '(?i)apache-coyote|tomcat') {
                $result.Framework = 'Tomcat'
                $result.Evidence  = 'Server header'
            }
            elseif ($server -match '(?i)undertow')  { $result.Framework = 'Undertow';  $result.Evidence = 'Server header' }
            elseif ($server -match '(?i)quarkus')   { $result.Framework = 'Quarkus';   $result.Evidence = 'Server header' }
            elseif ($server -match '(?i)WildFly')   { $result.Framework = 'WildFly';   $result.Evidence = 'Server header' }
        }
        if (-not $result.Framework -and $xpb -and $xpb -match '(?i)servlet|express|undertow') {
            $result.Evidence = 'X-Powered-By: ' + $xpb
        }
    }

    if ($result.Framework -and $result.Version) { return $result }
    if ($SafeProbeOnly) { return $result }

    # Spring Boot actuator root returns a HAL document listing management links.
    $act = Invoke-HttpProbe -Uri ($BaseUrl + '/actuator') -Method 'GET'
    if ($act.Success -and $act.StatusCode -eq 200 -and $act.Content -and $act.Content -match '"_links"') {
        $result.Framework = 'SpringBoot'
        $result.Evidence  = '/actuator returned HAL _links'

        $info = Invoke-HttpProbe -Uri ($BaseUrl + '/actuator/info') -Method 'GET'
        if ($info.Success -and $info.Content -and $info.Content -match '"version"\s*:\s*"([^"]+)"') {
            $result.Version = $Matches[1]
        }
        return $result
    }

    # Quarkus exposes its management surface under /q by convention.
    $q = Invoke-HttpProbe -Uri ($BaseUrl + '/q/health') -Method 'GET'
    if ($q.Success -and $q.StatusCode -eq 200) {
        $result.Framework = 'Quarkus'
        $result.Evidence  = '/q/health responded'
        return $result
    }

    return $result
}

function Resolve-Framework {
    <#
        Merges static and wire-level signals into a single verdict with an
        explicit confidence level:
          Confirmed - the running process identified itself over HTTP
          Inferred  - jar manifest or command line said so, unconfirmed
          Unknown   - nothing identified it
    #>
    param([string] $CommandLine, [string] $BaseUrl)

    $verdict = @{
        Framework  = 'Unknown'
        Version    = $null
        Confidence = 'Unknown'
        Evidence   = @()
        AppName    = $null
        ServerHeader = $null
    }

    $cmd = Resolve-FrameworkFromCommandLine -CommandLine $CommandLine
    if ($cmd.Framework -ne 'Unknown') {
        $verdict.Framework  = $cmd.Framework
        $verdict.Version    = $cmd.Version
        $verdict.Confidence = 'Inferred'
        $verdict.Evidence  += $cmd.Evidence
    }

    $man = Resolve-FrameworkFromJarManifest -CommandLine $CommandLine
    if ($man.Framework) {
        $verdict.Framework  = $man.Framework
        $verdict.Confidence = 'Inferred'
        $verdict.Evidence  += $man.Evidence
    }
    if ($man.Version -and -not $verdict.Version) { $verdict.Version = $man.Version }
    if ($man.AppName) { $verdict.AppName = $man.AppName }

    if ($BaseUrl) {
        $probe = Resolve-FrameworkFromProbe -BaseUrl $BaseUrl
        $verdict.ServerHeader = $probe.ServerHeader
        if ($probe.Framework) {
            $verdict.Framework  = $probe.Framework
            $verdict.Confidence = 'Confirmed'
            $verdict.Evidence  += $probe.Evidence
            if ($probe.Version) { $verdict.Version = $probe.Version }
        }
        elseif ($probe.Evidence) {
            $verdict.Evidence += $probe.Evidence
        }
    }

    return $verdict
}

# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

function New-ApiRecord {
    param(
        [string] $Source,
        [string] $Method,
        [string] $Path,
        [hashtable] $Context,
        [string] $Evidence,
        [int]    $HttpStatus,
        [string] $AuthChallenge,
        [string] $SpecSource,
        [int]    $ProbeMs,
        [string] $SpecHost
    )

    $ctxPath = $Context['ContextPath']
    $full    = $Path
    if ($ctxPath -and $ctxPath -ne '/' -and $Path -notlike ($ctxPath + '*')) {
        $full = ($ctxPath.TrimEnd('/')) + $Path
    }

    $rec = [pscustomobject]@{
        PSTypeName         = 'Harvest.ApiEndpoint'
        Server             = $env:COMPUTERNAME
        Fqdn               = $Context['Fqdn']
        ScanTimestamp      = $script:ScanTimestamp
        ScriptVersion      = $script:ScriptVersion

        Source             = $Source
        Sources            = $Source
        Runtime            = 'Java'
        Framework          = $Context['Framework']
        FrameworkVersion   = $Context['FrameworkVersion']
        FrameworkConfidence= $Context['FrameworkConfidence']
        FrameworkEvidence  = $Context['FrameworkEvidence']
        AppName            = $Context['AppName']

        JavaVersion        = $Context['JavaVersion']
        JavaVendor         = $Context['JavaVendor']
        ServiceName        = $Context['ServiceName']
        ServiceStartMode   = $Context['ServiceStartMode']
        ProcessUser        = $Context['ProcessUser']
        ProcessId          = $Context['ProcessId']
        ProcessStart       = $Context['ProcessStart']
        CommandLine        = $Context['CommandLine']

        ListenAddress      = $Context['ListenAddress']
        Exposure           = $Context['Exposure']
        Port               = $Context['Port']
        Scheme             = $Context['Scheme']
        TlsEnabled         = $Context['TlsEnabled']
        TlsProtocol        = $Context['TlsProtocol']
        CertSubject        = $Context['CertSubject']
        CertIssuer         = $Context['CertIssuer']
        CertNotAfter       = $Context['CertNotAfter']
        ServerHeader       = $Context['ServerHeader']

        Method             = $Method
        Host               = $Context['BaseUrl']
        SpecHost           = $SpecHost
        ContextPath        = $ctxPath
        Path               = $full
        NormalizedPath     = $null
        FullUrl            = $Context['BaseUrl'] + $full
        HttpStatus         = $HttpStatus
        AuthChallenge      = $AuthChallenge
        SpecSource         = $SpecSource
        ProbeMs            = $ProbeMs
        Evidence           = $Evidence
    }
    return $rec
}

# ---------------------------------------------------------------------------
# Discovery: Spring Boot actuator mappings
# ---------------------------------------------------------------------------

function Get-ActuatorMappings {
    param([string] $BaseUrl, [hashtable] $Context)

    $records = @()
    if ($SafeProbeOnly) { return $records }

    $resp = Invoke-HttpProbe -Uri ($BaseUrl + '/actuator/mappings') -Method 'GET'
    if (-not $resp.Success -or $resp.StatusCode -ne 200 -or -not $resp.Content) { return $records }

    try {
        $json = $resp.Content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Log ('actuator/mappings JSON parse failed on {0}' -f $BaseUrl) 'WARN'
        return $records
    }

    $skipExact  = @('/error', '/actuator', '/**', '/')
    $skipPrefix = @('/actuator/', '/error/')

    $emit = {
        param($patterns, $methods, $handler)
        if (-not $methods -or $methods.Count -eq 0) { $methods = @('*') }
        foreach ($p in $patterns) {
            $clean = ([string]$p).Trim().Trim('"')
            $clean = $clean -replace '\*\*$', ''
            if ($clean.Length -gt 1) { $clean = $clean.TrimEnd('/') }
            if (-not $clean) { continue }
            if ($skipExact -contains $clean) { continue }
            $skip = $false
            foreach ($sp in $skipPrefix) { if ($clean.StartsWith($sp)) { $skip = $true; break } }
            if ($skip) { continue }
            foreach ($mm in $methods) {
                $records += New-ApiRecord -Source 'ActuatorMappings' `
                                          -Method ([string]$mm).Trim().ToUpperInvariant() `
                                          -Path $clean `
                                          -Context $Context `
                                          -Evidence ('handler=' + $handler) `
                                          -HttpStatus 200 `
                                          -AuthChallenge $null `
                                          -SpecSource '/actuator/mappings'
            }
        }
    }

    try {
        $hasContexts = $json.PSObject.Properties.Name -contains 'contexts'

        if ($hasContexts) {
            # Boot 2.x/3.x: contexts.<name>.mappings.{dispatcherServlets|dispatcherHandlers}.<name>[]
            foreach ($ctxName in $json.contexts.PSObject.Properties.Name) {
                $ctx = $json.contexts.$ctxName
                if (-not ($ctx.PSObject.Properties.Name -contains 'mappings')) { continue }
                $dispatchers = $null
                foreach ($kind in @('dispatcherServlets', 'dispatcherHandlers')) {
                    if ($ctx.mappings.PSObject.Properties.Name -contains $kind) { $dispatchers = $ctx.mappings.$kind; break }
                }
                if ($null -eq $dispatchers) { continue }

                foreach ($dispName in $dispatchers.PSObject.Properties.Name) {
                    foreach ($m in $dispatchers.$dispName) {
                        $patterns = @(); $methods = @()
                        $cond = $null
                        if (($m.PSObject.Properties.Name -contains 'details') -and $m.details -and
                            ($m.details.PSObject.Properties.Name -contains 'requestMappingConditions')) {
                            $cond = $m.details.requestMappingConditions
                        }
                        if ($cond) {
                            if (($cond.PSObject.Properties.Name -contains 'patterns') -and $cond.patterns) { $patterns = @($cond.patterns) }
                            elseif (($cond.PSObject.Properties.Name -contains 'patternsCondition') -and $cond.patternsCondition -and $cond.patternsCondition.patterns) {
                                $patterns = @($cond.patternsCondition.patterns)
                            }
                            if (($cond.PSObject.Properties.Name -contains 'methods') -and $cond.methods) { $methods = @($cond.methods) }
                        }
                        if ($patterns.Count -eq 0 -and ($m.PSObject.Properties.Name -contains 'predicate') -and $m.predicate) {
                            $pred = [string]$m.predicate
                            if ($pred -match '\[(/[^\]]*)\]') {
                                $patterns = @(($Matches[1] -split '\s*\|\|\s*') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^/' })
                            }
                            if ($pred -match 'methods=\[([^\]]+)\]') { $methods = @(($Matches[1] -split ',') | ForEach-Object { $_.Trim() }) }
                            elseif ($pred -match '^\{(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s') { $methods = @($Matches[1]) }
                        }
                        if ($patterns.Count -eq 0) { continue }
                        $handler = if ($m.PSObject.Properties.Name -contains 'handler') { [string]$m.handler } else { '' }
                        & $emit $patterns $methods $handler
                    }
                }
            }
        }
        else {
            # Boot 1.x flat shape: keys like "{[/api/things],methods=[GET]}"
            foreach ($prop in $json.PSObject.Properties) {
                $key = $prop.Name
                if ($key -notmatch '\[(/[^\]]*)\]') { continue }
                $patterns = @(($Matches[1] -split '\s*\|\|\s*') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^/' })
                $methods  = @()
                if ($key -match 'methods=\[([^\]]+)\]') { $methods = @(($Matches[1] -split ',') | ForEach-Object { $_.Trim() }) }
                $handler = ''
                try { if ($prop.Value -and ($prop.Value.PSObject.Properties.Name -contains 'method')) { $handler = [string]$prop.Value.method } } catch { }
                & $emit $patterns $methods $handler
            }
        }
    }
    catch {
        Write-Log ('actuator/mappings walk failed on {0}: {1}' -f $BaseUrl, $_.Exception.Message) 'WARN'
    }

    Write-Log ('actuator/mappings yielded {0} route(s) on {1}' -f $records.Count, $BaseUrl) 'DEBUG'
    return $records
}

# ---------------------------------------------------------------------------
# Discovery: OpenAPI / Swagger specs
# ---------------------------------------------------------------------------

function Get-SpecHostCombos {
    <#
        Every host the spec declares, as @{ Host; BasePath }. OpenAPI 3 uses
        servers[].url (absolute or path-relative); Swagger 2 uses host +
        basePath + schemes[]. Each combination becomes its own row so the
        inventory records what the spec says the public address is, not
        only where the file was fetched from.
    #>
    param([object] $Spec, [string] $LocalBaseUrl)

    $combos = @()
    $names  = @($Spec.PSObject.Properties.Name)

    if (($names -contains 'servers') -and $Spec.servers) {
        foreach ($srv in @($Spec.servers)) {
            $u = $null
            try { $u = [string]$srv.url } catch { }
            if (-not $u -or $u -eq '/') { continue }
            if ($u -match '^/') {
                $combos += @{ Host = $LocalBaseUrl; BasePath = $u.TrimEnd('/') }
                continue
            }
            try {
                $uri = New-Object Uri($u)
                $hostUrl = '{0}://{1}' -f $uri.Scheme, $uri.Host
                if (-not $uri.IsDefaultPort) { $hostUrl += ':' + $uri.Port }
                $combos += @{ Host = $hostUrl; BasePath = $uri.AbsolutePath.TrimEnd('/') }
            }
            catch {
                # Templated server URLs ({scheme}://{host}) are not resolvable.
                $combos += @{ Host = $LocalBaseUrl; BasePath = '' }
            }
        }
    }

    if (($names -contains 'host') -and $Spec.host) {
        $specHost = [string]$Spec.host
        $basePath = ''
        if (($names -contains 'basePath') -and $Spec.basePath -and $Spec.basePath -ne '/') { $basePath = ([string]$Spec.basePath).TrimEnd('/') }
        $schemes = @('https')
        if (($names -contains 'schemes') -and $Spec.schemes) { $schemes = @($Spec.schemes | ForEach-Object { ([string]$_).ToLowerInvariant() }) }
        foreach ($sch in $schemes) {
            if ($sch -notmatch '^https?$') { continue }
            $combos += @{ Host = ('{0}://{1}' -f $sch, $specHost); BasePath = $basePath }
        }
    }

    if ($combos.Count -eq 0) { $combos += @{ Host = $LocalBaseUrl; BasePath = '' } }
    return $combos
}

function ConvertFrom-OpenApiJson {
    param([object] $Spec, [string] $SpecUrl, [hashtable] $Context)

    $records = @()
    if (-not ($Spec.PSObject.Properties.Name -contains 'paths')) { return $records }

    $combos = Get-SpecHostCombos -Spec $Spec -LocalBaseUrl $Context['BaseUrl']

    foreach ($p in $Spec.paths.PSObject.Properties.Name) {
        $ops = $Spec.paths.$p
        if ($null -eq $ops) { continue }
        foreach ($verb in $ops.PSObject.Properties.Name) {
            if ($verb -notmatch '^(get|put|post|delete|patch|head|options|trace)$') { continue }
            foreach ($c in $combos) {
                $records += New-ApiRecord -Source 'OpenApiSpec' `
                                          -Method $verb.ToUpperInvariant() `
                                          -Path ($c.BasePath + $p) `
                                          -Context $Context `
                                          -Evidence ('spec=' + $SpecUrl) `
                                          -HttpStatus 200 `
                                          -AuthChallenge $null `
                                          -SpecSource $SpecUrl `
                                          -SpecHost $c.Host
            }
        }
    }
    return $records
}

function ConvertFrom-OpenApiYaml {
    <#
        Deliberately lightweight: no YAML library on a stock Windows box.
        Handles the common two-space-indented shape well enough to get
        servers/host/basePath/schemes and the paths -> verb structure.
    #>
    param([string] $Yaml, [string] $SpecUrl, [hashtable] $Context)

    $records = @()
    $lines   = $Yaml -split "`r?`n"

    $combos = @()
    $inServers = $false; $specHost = $null; $basePath = ''; $schemes = @(); $inSchemes = $false
    foreach ($line in $lines) {
        $t = $line.TrimEnd()
        if ($t -match '^servers\s*:')  { $inServers = $true;  $inSchemes = $false; continue }
        if ($t -match '^schemes\s*:')  { $inSchemes = $true;  $inServers = $false; continue }
        if ($t -match '^\S') { $inServers = $false; $inSchemes = $false }

        if ($inServers -and $t -match '^\s+-?\s*url\s*:\s*[''"]?([^''"#]+)') {
            $u = $Matches[1].Trim()
            if ($u -match '^/') { $combos += @{ Host = $Context['BaseUrl']; BasePath = $u.TrimEnd('/') } }
            else {
                try {
                    $uri = New-Object Uri($u)
                    $hostUrl = '{0}://{1}' -f $uri.Scheme, $uri.Host
                    if (-not $uri.IsDefaultPort) { $hostUrl += ':' + $uri.Port }
                    $combos += @{ Host = $hostUrl; BasePath = $uri.AbsolutePath.TrimEnd('/') }
                } catch { $combos += @{ Host = $Context['BaseUrl']; BasePath = '' } }
            }
        }
        if ($inSchemes -and $t -match '^\s+-\s*(https?)\s*$') { $schemes += $Matches[1] }
        if ($t -match '^host\s*:\s*[''"]?([^''"#\s]+)')     { $specHost = $Matches[1] }
        if ($t -match '^basePath\s*:\s*[''"]?([^''"#\s]+)') { $basePath = $Matches[1].TrimEnd('/') }
    }
    if ($specHost) {
        if ($schemes.Count -eq 0) { $schemes = @('https') }
        foreach ($sch in $schemes) { $combos += @{ Host = ('{0}://{1}' -f $sch, $specHost); BasePath = $basePath } }
    }
    if ($combos.Count -eq 0) { $combos += @{ Host = $Context['BaseUrl']; BasePath = '' } }

    $inPaths = $false; $current = $null; $pathIndent = -1
    foreach ($line in $lines) {
        $t = $line.TrimEnd()
        if ($t -match '^paths\s*:') { $inPaths = $true; continue }
        if (-not $inPaths) { continue }
        if ($t -match '^\S') { break }

        if ($t -match '^(\s+)([''"]?)(/[^''":\s]*)\2\s*:\s*$') {
            $indent = $Matches[1].Length
            if ($pathIndent -lt 0 -or $indent -eq $pathIndent) { $pathIndent = $indent; $current = $Matches[3]; continue }
        }
        if ($current -and $t -match '^(\s+)(get|put|post|delete|patch|head|options|trace)\s*:') {
            if ($Matches[1].Length -gt $pathIndent) {
                $verb = $Matches[2].ToUpperInvariant()
                foreach ($c in $combos) {
                    $records += New-ApiRecord -Source 'OpenApiSpec' `
                                              -Method $verb `
                                              -Path ($c.BasePath + $current) `
                                              -Context $Context `
                                              -Evidence ('spec=' + $SpecUrl) `
                                              -HttpStatus 200 `
                                              -AuthChallenge $null `
                                              -SpecSource $SpecUrl `
                                              -SpecHost $c.Host
                }
            }
        }
    }
    return $records
}

function ConvertFrom-OpenApiSpec {
    <#
        Dispatch on content: JSON first, YAML if the body looks like a spec.
    #>
    param([string] $SpecText, [string] $SpecUrl, [hashtable] $Context)

    if (-not $SpecText) { return @() }
    $body = $SpecText.Trim()

    if ($body.StartsWith('{')) {
        try {
            $spec = $body | ConvertFrom-Json -ErrorAction Stop
            return ConvertFrom-OpenApiJson -Spec $spec -SpecUrl $SpecUrl -Context $Context
        } catch { return @() }
    }
    if ($body -match '^(openapi|swagger)\s*:' -or $body -match '(?m)^paths\s*:') {
        return ConvertFrom-OpenApiYaml -Yaml $body -SpecUrl $SpecUrl -Context $Context
    }
    return @()
}

function Find-SpecFilesUnderPath {
    param([string] $SearchRoot, [hashtable] $Context)

    $records = @()
    if ($DisableSpecScan) { return $records }
    if (-not $SearchRoot -or -not (Test-Path $SearchRoot)) { return $records }

    $names = @('openapi.json', 'openapi.yaml', 'openapi.yml', 'swagger.json', 'swagger.yaml', 'swagger.yml')
    try {
        $files = Get-ChildItem -Path $SearchRoot -Recurse -Depth $SearchDepth -File -Include $names -ErrorAction SilentlyContinue |
                 Select-Object -First $MaxSpecFiles
        foreach ($f in $files) {
            try {
                $content = Get-Content $f.FullName -Raw -ErrorAction Stop
                $parsed  = ConvertFrom-OpenApiSpec -SpecText $content -SpecUrl $f.FullName -Context $Context
                if ($parsed.Count -gt 0) {
                    Write-Log ('{0} yielded {1} route(s)' -f $f.FullName, $parsed.Count) 'DEBUG'
                    $records += $parsed
                }
            } catch { }
        }
    } catch { }
    return $records
}

function Get-SpecDerivedApis {
    param([string] $BaseUrl, [hashtable] $Context)

    $records = @()
    if ($SafeProbeOnly) { return $records }

    $fw    = $Context['Framework']
    $paths = if ($script:SpecPathsByFramework.ContainsKey($fw)) {
                 $script:SpecPathsByFramework[$fw]
             } else {
                 $script:SpecPathsByFramework['Unknown']
             }

    # Springfox publishes its spec locations dynamically.
    $sr = Invoke-HttpProbe -Uri ($BaseUrl + '/swagger-resources') -Method 'GET'
    if ($sr.Success -and $sr.StatusCode -eq 200 -and $sr.Content) {
        try {
            $resources = $sr.Content | ConvertFrom-Json -ErrorAction Stop
            foreach ($r in $resources) {
                if (-not $r.location) { continue }
                $loc = [string]$r.location
                if ($loc -match '^https?://') { $loc = $loc -replace '^https?://[^/]+', '' }
                if ($loc -match '^/') { $paths = @($paths) + $loc }
            }
        } catch { }
    }

    foreach ($sp in ($paths | Select-Object -Unique)) {
        $uri  = $BaseUrl + $sp
        $resp = Invoke-HttpProbe -Uri $uri -Method 'GET'
        if ($resp.Success -and $resp.StatusCode -eq 200 -and $resp.Content) {
            $parsed = ConvertFrom-OpenApiSpec -SpecText $resp.Content -SpecUrl $uri -Context $Context
            if ($parsed.Count -gt 0) {
                Write-Log ('{0} yielded {1} route(s)' -f $uri, $parsed.Count) 'DEBUG'
                $records += $parsed
            }
        }
    }
    return $records
}

# ---------------------------------------------------------------------------
# Discovery: Tomcat filesystem
# ---------------------------------------------------------------------------

function Find-TomcatInstalls {
    param([string[]] $Roots)

    $found = @()

    # Authoritative first: catalina.base/home of every running Java process,
    # then machine-level CATALINA_* env vars. These catch deep install paths
    # the depth-limited filesystem walk below would miss.
    foreach ($p in (Get-CachedProcessTable).Values) {
        $base = Get-CatalinaBaseFromCommandLine -CommandLine $p.CommandLine
        if ($base -and (Test-Path (Join-Path $base 'conf\server.xml'))) { $found += $base }
    }
    foreach ($var in @('CATALINA_BASE', 'CATALINA_HOME')) {
        $val = [Environment]::GetEnvironmentVariable($var, 'Machine')
        if ($val -and (Test-Path (Join-Path $val 'conf\server.xml'))) { $found += $val.TrimEnd('\\') }
    }

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            $candidates = Get-ChildItem -Path $root -Directory -Depth 3 -ErrorAction SilentlyContinue |
                          Where-Object { Test-Path (Join-Path $_.FullName 'conf\server.xml') }
            foreach ($c in $candidates) { $found += $c.FullName }
        } catch { }
    }
    return ($found | Select-Object -Unique)
}

function Get-TomcatVersion {
    param([string] $CatalinaHome)
    try {
        $notes = Join-Path $CatalinaHome 'RELEASE-NOTES'
        if (Test-Path $notes) {
            $head = Get-Content $notes -TotalCount 40 -ErrorAction SilentlyContinue
            foreach ($line in $head) {
                if ($line -match 'Apache Tomcat Version\s+([\d\.]+)') { return $Matches[1] }
            }
        }
        if ($CatalinaHome -match 'tomcat[-_]?([\d\.]+)') { return $Matches[1] }
    } catch { }
    return $null
}

function Get-TomcatApis {
    param([string] $CatalinaHome, [hashtable] $BaseContext)

    $records = @()
    $fqdn    = $BaseContext['Fqdn']

    # Connectors from server.xml give the real ports and schemes.
    $connectors = @()
    try {
        $serverXml = Join-Path $CatalinaHome 'conf\server.xml'
        [xml]$xml  = Get-Content $serverXml -ErrorAction Stop
        foreach ($c in $xml.Server.Service.Connector) {
            if (-not $c.port) { continue }
            # AJP connectors are not HTTP; probing them only burns the timeout.
            if ($c.protocol -and $c.protocol -match '(?i)ajp') { continue }
            $isSsl = ($c.SSLEnabled -eq 'true') -or ($c.scheme -eq 'https')
            $addr  = if ($c.address) { [string]$c.address } else { '0.0.0.0' }
            $connectors += [pscustomobject]@{
                Port      = [int]$c.port
                Scheme    = if ($isSsl) { 'https' } else { 'http' }
                Address   = $addr
                ProbeHost = if ($addr -match '^(127\.|localhost$|::1$)') { '127.0.0.1' } else { $fqdn }
            }
        }
    }
    catch {
        Write-Log ('server.xml parse failed in {0}: {1}' -f $CatalinaHome, $_.Exception.Message) 'WARN'
        return $records
    }
    if ($connectors.Count -eq 0) { return $records }

    $tomcatVersion = Get-TomcatVersion -CatalinaHome $CatalinaHome
    foreach ($conn in $connectors) { $script:TomcatPorts[$conn.Port] = $CatalinaHome }

    # Deployed contexts: exploded dirs and WAR files under webapps.
    $contexts = @()
    $webapps  = Join-Path $CatalinaHome 'webapps'
    if (Test-Path $webapps) {
        foreach ($d in (Get-ChildItem $webapps -Directory -ErrorAction SilentlyContinue)) {
            $ctx = if ($d.Name -eq 'ROOT') { '/' } else { '/' + $d.Name }
            $contexts += [pscustomobject]@{ Context = $ctx; Dir = $d.FullName }
        }
        foreach ($w in (Get-ChildItem $webapps -Filter '*.war' -File -ErrorAction SilentlyContinue)) {
            $name = [IO.Path]::GetFileNameWithoutExtension($w.Name)
            $ctx  = if ($name -eq 'ROOT') { '/' } else { '/' + $name }
            if (-not ($contexts | Where-Object { $_.Context -eq $ctx })) {
                $contexts += [pscustomobject]@{ Context = $ctx; Dir = $null }
            }
        }
    }

    foreach ($conn in $connectors) {
        if (Test-OutOfTime) { return $records }
        $baseUrl  = '{0}://{1}:{2}' -f $conn.Scheme, $fqdn, $conn.Port
        $probeUrl = '{0}://{1}:{2}' -f $conn.Scheme, $conn.ProbeHost, $conn.Port
        $tls      = Test-TlsEndpoint -TargetHost $conn.ProbeHost -Port $conn.Port

        foreach ($c in $contexts) {
            $ctxObj = $BaseContext.Clone()
            $ctxObj['BaseUrl']            = $baseUrl
            $ctxObj['ProbeUrl']           = $probeUrl
            $ctxObj['Port']               = $conn.Port
            $ctxObj['Scheme']             = $conn.Scheme
            $ctxObj['ListenAddress']      = $conn.Address
            $ctxObj['Exposure']           = if ($conn.ProbeHost -eq '127.0.0.1') { 'Loopback' } elseif ($conn.Address -eq '0.0.0.0') { 'AllInterfaces' } else { 'SpecificInterface' }
            $ctxObj['ContextPath']        = $c.Context
            $ctxObj['Framework']          = 'Tomcat'
            $ctxObj['FrameworkVersion']   = $tomcatVersion
            $ctxObj['FrameworkConfidence']= 'Confirmed'
            $ctxObj['FrameworkEvidence']  = 'server.xml at ' + $CatalinaHome
            $ctxObj['AppName']            = $c.Context.TrimStart('/')
            $ctxObj['TlsEnabled']         = $tls.TlsEnabled
            $ctxObj['TlsProtocol']        = $tls.TlsProtocol
            $ctxObj['CertSubject']        = $tls.CertSubject
            $ctxObj['CertIssuer']         = $tls.CertIssuer
            $ctxObj['CertNotAfter']       = $tls.CertNotAfter

            # web.xml servlet mappings are the authoritative declared routes.
            # A servlet mapping accepts any method, so Method is '*'.
            if ($c.Dir) {
                $webXmls = @()
                $primary = Join-Path $c.Dir 'WEB-INF\web.xml'
                if (Test-Path $primary) { $webXmls += $primary }
                try {
                    $nested = Get-ChildItem -Path $c.Dir -Recurse -Depth $SearchDepth -Filter 'web.xml' -File -ErrorAction SilentlyContinue |
                              Where-Object { $_.FullName -ne $primary } | Select-Object -First 5
                    foreach ($n in $nested) { $webXmls += $n.FullName }
                } catch { }

                foreach ($webXml in $webXmls) {
                    try {
                        [xml]$wx = Get-Content $webXml -Raw -ErrorAction Stop
                        $ns = $wx.DocumentElement.NamespaceURI
                        if ($ns) {
                            $mgr = New-Object Xml.XmlNamespaceManager($wx.NameTable)
                            $mgr.AddNamespace('j', $ns)
                            $nodes = $wx.SelectNodes('//j:servlet-mapping', $mgr)
                        } else {
                            $nodes = $wx.SelectNodes('//servlet-mapping')
                        }
                        foreach ($m in $nodes) {
                            $servletName = $null
                            $patternsOut = @()
                            foreach ($child in $m.ChildNodes) {
                                if ($child.LocalName -eq 'servlet-name') { $servletName = $child.InnerText.Trim() }
                                if ($child.LocalName -eq 'url-pattern')  { $patternsOut += $child.InnerText.Trim() }
                            }
                            foreach ($pattern in $patternsOut) {
                                if (-not $pattern) { continue }
                                $clean = ($pattern -replace '\*$', '')
                                if ($clean.Length -gt 1) { $clean = $clean.TrimEnd('/') }
                                if (-not $clean) { $clean = '/' }
                                $records += New-ApiRecord -Source 'TomcatWebXml' `
                                                          -Method '*' `
                                                          -Path $clean `
                                                          -Context $ctxObj `
                                                          -Evidence ('servlet=' + $servletName) `
                                                          -HttpStatus $null `
                                                          -AuthChallenge $null `
                                                          -SpecSource $webXml
                            }
                        }
                    }
                    catch {
                        Write-Log ('web.xml parse failed at {0}: {1}' -f $webXml, $_.Exception.Message) 'DEBUG'
                    }
                }

                # On-disk spec files shipped inside the webapp (JSON and YAML).
                $records += Find-SpecFilesUnderPath -SearchRoot $c.Dir -Context $ctxObj
            }

            # Live introspection against the deployed context. A Spring Boot
            # WAR inside standalone Tomcat still exposes actuator here.
            $ctxUrl = $probeUrl + $c.Context.TrimEnd('/')
            $records += Get-ActuatorMappings -BaseUrl $ctxUrl -Context $ctxObj
            $records += Get-SpecDerivedApis  -BaseUrl $ctxUrl -Context $ctxObj
        }
    }

    return $records
}

# ---------------------------------------------------------------------------
# Discovery: process-derived
# ---------------------------------------------------------------------------

function Get-ProcessDerivedApis {
    param([hashtable] $BaseContext)

    $records   = @()
    $procs     = Get-CachedProcessTable
    $listeners = Get-CachedTcpListeners
    $services  = Get-CachedServiceTable
    $fqdn      = $BaseContext['Fqdn']

    foreach ($javaPid in $procs.Keys) {
        $proc  = $procs[$javaPid]
        $ports = $listeners | Where-Object { $_.ProcessId -eq $javaPid }
        if (-not $ports) {
            Write-Log ('PID {0} is Java but not listening on any TCP port' -f $javaPid) 'DEBUG'
            continue
        }

        $javaInfo = Get-JavaRuntimeInfo -ExePath $proc.ExePath -CommandLine $proc.CommandLine
        $svc      = if ($services.ContainsKey($javaPid)) { $services[$javaPid] } else { $null }
        $ctxPath  = Get-ContextPathFromCommandLine -CommandLine $proc.CommandLine
        $jarDir   = Get-JarDirectoryFromCommandLine -CommandLine $proc.CommandLine
        if (-not $ctxPath -and $jarDir) { $ctxPath = Get-ContextPathFromConfig -WorkDir $jarDir }
        $mgmtPort = Get-ManagementPortFromCommandLine -CommandLine $proc.CommandLine
        $admPort  = Get-DropwizardAdminPortFromCommandLine -CommandLine $proc.CommandLine
        $skip     = @(Get-NonHttpPortsFromCommandLine -CommandLine $proc.CommandLine)
        if ($ExcludePorts) { $skip += $ExcludePorts }

        # Deduplicate ports - a process may bind the same port on several
        # addresses. Keep the broadest binding for exposure classification.
        $portGroups = $ports | Group-Object Port

        foreach ($group in $portGroups) {
            if (Test-OutOfTime) { return $records }
            $port      = [int]$group.Name
            if ($skip -contains $port) {
                Write-Log ('PID {0} port {1} excluded (JMX/JDWP/-ExcludePorts)' -f $javaPid, $port) 'DEBUG'
                continue
            }
            $addresses = @($group.Group | ForEach-Object { $_.LocalAddress })
            $sw        = [Diagnostics.Stopwatch]::StartNew()

            $exposure = 'Loopback'
            if ($addresses -contains '0.0.0.0' -or $addresses -contains '::') { $exposure = 'AllInterfaces' }
            elseif ($addresses | Where-Object { $_ -notmatch '^(127\.|::1$)' }) { $exposure = 'SpecificInterface' }

            # Probe where the socket actually is; record the fleet-addressable host.
            $probeHost = Get-ProbeHost -Fqdn $fqdn -Exposure $exposure -Addresses $addresses
            $tls       = Test-TlsEndpoint -TargetHost $probeHost.Trim('[', ']') -Port $port
            $scheme    = if ($tls.TlsEnabled) { 'https' } else { 'http' }
            $probeUrl  = '{0}://{1}:{2}' -f $scheme, $probeHost, $port
            $baseUrl   = '{0}://{1}:{2}' -f $scheme, $fqdn, $port

            $fw = Resolve-Framework -CommandLine $proc.CommandLine -BaseUrl $probeUrl

            $appName = $fw.AppName
            if (-not $appName) { $appName = Get-AppNameFromCommandLine -CommandLine $proc.CommandLine }

            $ctxObj = $BaseContext.Clone()
            $ctxObj['BaseUrl']             = $baseUrl
            $ctxObj['ProbeUrl']            = $probeUrl
            $ctxObj['Port']                = $port
            $ctxObj['Scheme']              = $scheme
            $ctxObj['ContextPath']         = $ctxPath
            $ctxObj['ListenAddress']       = ($addresses -join ',')
            $ctxObj['Exposure']            = $exposure
            $ctxObj['Framework']           = $fw.Framework
            $ctxObj['FrameworkVersion']    = $fw.Version
            $ctxObj['FrameworkConfidence'] = $fw.Confidence
            $ctxObj['FrameworkEvidence']   = (($fw.Evidence | Where-Object { $_ }) -join '; ')
            $ctxObj['ServerHeader']        = $fw.ServerHeader
            $ctxObj['AppName']             = $appName
            $ctxObj['JavaVersion']         = $javaInfo.JavaVersion
            $ctxObj['JavaVendor']          = $javaInfo.JavaVendor
            $ctxObj['ServiceName']         = if ($svc) { $svc.ServiceName } else { $null }
            $ctxObj['ServiceStartMode']    = if ($svc) { $svc.StartMode }   else { $null }
            $ctxObj['ProcessUser']         = $proc.Owner
            $ctxObj['ProcessId']           = $javaPid
            $ctxObj['ProcessStart']        = $proc.StartTime
            $ctxObj['CommandLine']         = if ($IncludeCommandLine) { Protect-CommandLine $proc.CommandLine } else { $null }
            $ctxObj['TlsEnabled']          = $tls.TlsEnabled
            $ctxObj['TlsProtocol']         = $tls.TlsProtocol
            $ctxObj['CertSubject']         = $tls.CertSubject
            $ctxObj['CertIssuer']          = $tls.CertIssuer
            $ctxObj['CertNotAfter']        = $tls.CertNotAfter

            Write-Log ('PID {0} port {1} -> {2} ({3})' -f $javaPid, $port, $fw.Framework, $fw.Confidence) 'DEBUG'

            # Authoritative sources first. Fetch via ProbeUrl (reachable),
            # record under BaseUrl (fleet-addressable).
            $routeRecords = @()
            $ctxRoot = if ($ctxPath -and $ctxPath -ne '/') { $probeUrl + $ctxPath.TrimEnd('/') } else { $probeUrl }
            $routeRecords += Get-ActuatorMappings   -BaseUrl $ctxRoot -Context $ctxObj
            $routeRecords += Get-SpecDerivedApis    -BaseUrl $ctxRoot -Context $ctxObj
            if ($ctxRoot -ne $probeUrl) {
                # Some apps serve introspection at the root regardless of context path.
                $routeRecords += Get-ActuatorMappings -BaseUrl $probeUrl -Context $ctxObj
                $routeRecords += Get-SpecDerivedApis  -BaseUrl $probeUrl -Context $ctxObj
            }
            if ($jarDir) { $routeRecords += Find-SpecFilesUnderPath -SearchRoot $jarDir -Context $ctxObj }

            # Separate management (Spring Boot) or admin (Dropwizard) port.
            # Each gets its own TLS probe and is tried on loopback first,
            # since these are usually bound to 127.0.0.1 only.
            foreach ($aux in @(@{ Port = $mgmtPort; Kind = 'management' }, @{ Port = $admPort; Kind = 'admin' })) {
                $auxPort = $aux.Port
                if (-not $auxPort -or $auxPort -eq $port) { continue }
                $auxKey = '{0}:{1}' -f $javaPid, $auxPort
                if ($script:AuxPortsDone.ContainsKey($auxKey)) { continue }
                $script:AuxPortsDone[$auxKey] = $true

                foreach ($auxHost in @('127.0.0.1', $fqdn)) {
                    $auxTls    = Test-TlsEndpoint -TargetHost $auxHost -Port $auxPort
                    $auxScheme = if ($auxTls.TlsEnabled) { 'https' } else { 'http' }
                    $auxProbe  = '{0}://{1}:{2}' -f $auxScheme, $auxHost, $auxPort
                    $auxCtx    = $ctxObj.Clone()
                    $auxCtx['BaseUrl']      = '{0}://{1}:{2}' -f $auxScheme, $fqdn, $auxPort
                    $auxCtx['ProbeUrl']     = $auxProbe
                    $auxCtx['Port']         = $auxPort
                    $auxCtx['Scheme']       = $auxScheme
                    $auxCtx['TlsEnabled']   = $auxTls.TlsEnabled
                    $auxCtx['TlsProtocol']  = $auxTls.TlsProtocol
                    $auxCtx['CertSubject']  = $auxTls.CertSubject
                    $auxCtx['CertIssuer']   = $auxTls.CertIssuer
                    $auxCtx['CertNotAfter'] = $auxTls.CertNotAfter

                    $auxRecords = @()
                    if ($aux.Kind -eq 'management') {
                        $auxRecords += Get-ActuatorMappings -BaseUrl $auxProbe -Context $auxCtx
                    }
                    else {
                        foreach ($ap in @('/healthcheck', '/metrics', '/threads', '/ping')) {
                            $pr = Invoke-HttpProbe -Uri ($auxProbe + $ap) -Method 'HEAD'
                            if ($pr.Success -and $pr.StatusCode -ne 404) {
                                $auxRecords += New-ApiRecord -Source 'DropwizardAdmin' -Method 'GET' -Path $ap -Context $auxCtx `
                                                             -Evidence ('PID={0}; AdminPort={1}' -f $javaPid, $auxPort) `
                                                             -HttpStatus $pr.StatusCode -AuthChallenge (Get-HeaderValue $pr.Headers 'WWW-Authenticate') `
                                                             -SpecSource 'static admin-path probe'
                            }
                        }
                    }
                    if ($auxRecords.Count -gt 0) {
                        Write-Log ('PID {0} {1} port {2} answered on {3}' -f $javaPid, $aux.Kind, $auxPort, $auxHost) 'DEBUG'
                        $routeRecords += $auxRecords
                        break
                    }
                }
            }

            $elapsed = [int]$sw.ElapsedMilliseconds
            foreach ($r in $routeRecords) { $r.ProbeMs = $elapsed }

            if ($routeRecords.Count -gt 0) {
                $records += $routeRecords
                continue
            }

            # A Tomcat port already covered by server.xml/web.xml discovery
            # gets no guessed candidates - they would only duplicate it. A
            # Tomcat whose install was not located still falls through.
            if ($script:TomcatPorts.ContainsKey($port)) {
                Write-Log ('PID {0} port {1} covered by Tomcat install {2}' -f $javaPid, $port, $script:TomcatPorts[$port]) 'DEBUG'
                continue
            }

            # Nothing authoritative answered. Emit candidates and label them as
            # such so downstream consumers do not mistake guesses for findings.
            foreach ($p in $script:FallbackPaths) {
                $probe = Invoke-HttpProbe -Uri ($probeUrl + $p) -Method 'HEAD'
                if (-not $probe.Success) { continue }
                if ($probe.StatusCode -eq 404) { continue }

                $authChallenge = Get-HeaderValue $probe.Headers 'WWW-Authenticate'
                $records += New-ApiRecord -Source 'ProcessDiscovery-Candidate' `
                                          -Method 'GET' `
                                          -Path $p `
                                          -Context $ctxObj `
                                          -Evidence ('PID={0}; Name={1}; Port={2}' -f $javaPid, $proc.Name, $port) `
                                          -HttpStatus $probe.StatusCode `
                                          -AuthChallenge $authChallenge `
                                          -SpecSource 'static known-path probe' `
                                          -ProbeMs ([int]$sw.ElapsedMilliseconds)
            }
        }
    }

    return $records
}

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

function Normalize-ApiResults {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Apis
    )

    if (-not $Apis -or $Apis.Count -eq 0) { return @() }

    $byKey = [ordered]@{}
    $rank  = @{ 'ActuatorMappings' = 4; 'TomcatWebXml' = 3; 'OpenApiSpec' = 2; 'DropwizardAdmin' = 1; 'ProcessDiscovery-Candidate' = 0 }

    foreach ($a in $Apis) {
        if ($null -eq $a) { continue }

        # Collapse identifier segments so one route does not become a thousand
        # rows. UUID, numeric id, Mongo ObjectId, and Spring path variables.
        $norm = $a.Path
        if ($norm) {
            $norm = [regex]::Replace($norm, '(?i)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}')
            $norm = [regex]::Replace($norm, '(?i)/[0-9a-f]{24}(?=/|$)', '/{objectId}')
            $norm = [regex]::Replace($norm, '/\d+(?=/|$)', '/{id}')
            $norm = [regex]::Replace($norm, '/\{[^}]+\}', '/{param}')
            $norm = $norm -replace '/{2,}', '/'
            if ($norm.Length -gt 1) { $norm = $norm.TrimEnd('/') }
            if (-not $norm) { $norm = '/' }
        }
        $a.NormalizedPath = $norm

        # One endpoint is one row. The same route seen by several sources is
        # merged into a single row carrying every source that saw it, with
        # the most authoritative source's metadata kept.
        $hostKey = if ($a.SpecHost) { $a.SpecHost } else { $a.Host }
        $key = '{0}|{1}|{2}' -f $hostKey.ToLowerInvariant(), $a.Method, $norm

        if ($byKey.Contains($key)) {
            $existing = $byKey[$key]
            $srcList  = @(@($existing.Sources -split ';\s*') + $a.Source | Where-Object { $_ } | Select-Object -Unique)
            $merged   = ($srcList -join '; ')
            $er = if ($rank.ContainsKey($existing.Source)) { $rank[$existing.Source] } else { 0 }
            $nr = if ($rank.ContainsKey($a.Source))        { $rank[$a.Source] }        else { 0 }
            if ($nr -gt $er) { $byKey[$key] = $a }
            $byKey[$key].Sources = $merged
            continue
        }
        $byKey[$key] = $a
    }

    $out = @($byKey.Values)
    return $out
}

# ---------------------------------------------------------------------------
# Tanium output
# ---------------------------------------------------------------------------

function Write-TaniumOutput {
    <#
        Tanium sensors return lines of text and have a per-endpoint result
        size limit, so this writes a compact pipe-delimited row per endpoint
        (no command line, no evidence, no cert subject) plus a one-row
        summary. The companion sensor reads these files verbatim.
    #>
    param([object[]] $Records, [string] $Directory, [datetime] $RunStart)

    try {
        if (-not (Test-Path $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }

        $sanitize = { param($v) if ($null -eq $v) { '' } else { ([string]$v) -replace '[|\r\n]', ' ' } }

        $lines = @()
        foreach ($r in @($Records)) {
            $lines += ((@(
                $r.Fqdn, $r.Method, $r.NormalizedPath, $r.Host, $r.SpecHost,
                $r.Framework, $r.FrameworkVersion, $r.FrameworkConfidence, $r.AppName,
                $r.Port, $r.Scheme, $r.Exposure, $r.TlsEnabled, $r.CertNotAfter,
                $r.HttpStatus, $r.AuthChallenge, $r.ServiceName, $r.ProcessUser,
                $r.JavaVersion, $r.Sources
            ) | ForEach-Object { & $sanitize $_ }) -join '|')
        }
        $resultsPath = Join-Path $Directory 'results.txt'
        [IO.File]::WriteAllLines($resultsPath, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))

        $frameworks = @($Records | Where-Object { $_.Framework -and $_.Framework -ne 'Unknown' } |
                        Select-Object -ExpandProperty Framework -Unique) -join ','
        $summary = @(
            'Status='        + $(if ($script:TimedOut) { 'Partial' } else { 'Complete' })
            'ScriptVersion=' + $script:ScriptVersion
            'ScanTimestamp=' + $script:ScanTimestamp
            'Fqdn='          + (Get-LocalFqdn)
            'Endpoints='     + @($Records).Count
            'JavaProcesses=' + (Get-CachedProcessTable).Count
            'Frameworks='    + $frameworks
            'Loopback='      + @($Records | Where-Object { $_.Exposure -eq 'Loopback' }).Count
            'Exposed='       + @($Records | Where-Object { $_.Exposure -ne 'Loopback' }).Count
            'Candidates='    + @($Records | Where-Object { $_.Source -eq 'ProcessDiscovery-Candidate' }).Count
            'RuntimeSec='    + [int]((Get-Date) - $RunStart).TotalSeconds
            'LogPath='       + $script:LogPath
        )
        $summaryPath = Join-Path $Directory 'summary.txt'
        [IO.File]::WriteAllLines($summaryPath, [string[]]$summary, (New-Object Text.UTF8Encoding($false)))

        Write-Log ('Wrote Tanium output: {0} ({1} rows), {2}' -f $resultsPath, $lines.Count, $summaryPath)
    }
    catch {
        Write-Log ('Tanium output failed: {0}' -f $_.Exception.Message) 'ERROR'
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Invoke-Harvest {
    Write-Log ('Harvest-ApiInventory {0} starting on {1}' -f $script:ScriptVersion, $env:COMPUTERNAME)

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log 'PowerShell 5.1 or later is required.' 'ERROR'
        return @()
    }

    Initialize-Tls
    if ($MaxRuntimeSec -gt 0) { $script:Deadline = (Get-Date).AddSeconds($MaxRuntimeSec) }
    $runStart = Get-Date

    $fqdn = Get-LocalFqdn
    Write-Log ('Resolved hostname: {0}' -f $fqdn)

    $baseContext = @{
        Fqdn                = $fqdn
        BaseUrl             = $null
        Port                = $null
        Scheme              = 'http'
        ContextPath         = $null
        ProbeUrl            = $null
        ListenAddress       = $null
        Exposure            = $null
        Framework           = 'Unknown'
        FrameworkVersion    = $null
        FrameworkConfidence = 'Unknown'
        FrameworkEvidence   = $null
        ServerHeader        = $null
        AppName             = $null
        JavaVersion         = $null
        JavaVendor          = $null
        ServiceName         = $null
        ServiceStartMode    = $null
        ProcessUser         = $null
        ProcessId           = $null
        ProcessStart        = $null
        CommandLine         = $null
        TlsEnabled          = $false
        TlsProtocol         = $null
        CertSubject         = $null
        CertIssuer          = $null
        CertNotAfter        = $null
    }

    $all = @()

    # Tomcat filesystem scan first, so process discovery knows which ports
    # are already covered authoritatively.
    $roots = $ScanRoots
    if (-not $roots -or $roots.Count -eq 0) {
        try {
            $roots = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                       ForEach-Object { $_.DeviceID + '\' })
        }
        catch { $roots = @('C:\') }
    }

    foreach ($catalinaHome in (Find-TomcatInstalls -Roots $roots)) {
        if (Test-OutOfTime) { break }
        Write-Log ('Tomcat install found: {0}' -f $catalinaHome)
        $all += Get-TomcatApis -CatalinaHome $catalinaHome -BaseContext $baseContext
    }

    # Process discovery covers every other listening JVM, and any Tomcat
    # whose install directory could not be located.
    if (-not (Test-OutOfTime)) { $all += Get-ProcessDerivedApis -BaseContext $baseContext }

    $normalized = Normalize-ApiResults -Apis $all
    Write-Log ('Discovered {0} endpoint(s), {1} after normalization' -f $all.Count, $normalized.Count)

    if ($OutputCsv) {
        try {
            $dir = Split-Path $OutputCsv -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $normalized | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
            Write-Log ('Wrote {0}' -f $OutputCsv)
        }
        catch {
            Write-Log ('CSV export failed: {0}' -f $_.Exception.Message) 'ERROR'
        }
    }

    if ($TaniumOutput) { Write-TaniumOutput -Records $normalized -Directory $TaniumOutput -RunStart $runStart }

    return $normalized
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if (-not (Enter-SingleInstance)) { return @() }

try {
    Invoke-Harvest
}
finally {
    Exit-SingleInstance
    Write-Log 'Run complete.'
}
