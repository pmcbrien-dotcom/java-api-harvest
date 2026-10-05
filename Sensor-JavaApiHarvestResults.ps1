# Tanium Sensor: Java API Harvest Results
# Type: PowerShell  |  Max age: 15 minutes  |  Result type: Text
# Returns one line per discovered endpoint written by Harvest-ApiInventory.ps1
# (-TaniumOutput). Column delimiter is the pipe character.
#
# Columns (set these as the sensor's column names, pipe-delimited):
#   Fqdn|Method|Path|Host|SpecHost|Framework|FrameworkVersion|Confidence|AppName|Port|Scheme|Exposure|Tls|CertNotAfter|HttpStatus|AuthChallenge|ServiceName|ProcessUser|JavaVersion|Sources

$path = Join-Path $env:ProgramData 'ApiHarvest\results.txt'

if (-not (Test-Path $path)) {
    Write-Output 'Not Run'
    exit 0
}

$age = (Get-Date) - (Get-Item $path).LastWriteTime
if ($age.TotalDays -gt 7) {
    Write-Output ('Stale|' + [int]$age.TotalDays + ' days')
    exit 0
}

$lines = Get-Content -Path $path -ErrorAction SilentlyContinue
if (-not $lines -or $lines.Count -eq 0) {
    Write-Output 'No Endpoints'
    exit 0
}

# Tanium truncates very large per-endpoint results; cap and flag.
$cap = 5000
if ($lines.Count -gt $cap) {
    $lines[0..($cap - 1)] | ForEach-Object { Write-Output $_ }
    Write-Output ('TRUNCATED|' + $lines.Count + ' total rows, showing ' + $cap)
} else {
    $lines | ForEach-Object { Write-Output $_ }
}
