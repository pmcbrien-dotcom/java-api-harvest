# Tanium Sensor: Java API Harvest Summary
# Type: PowerShell  |  Max age: 15 minutes  |  Result type: Text
# Returns one line per host summarizing the last Harvest-ApiInventory.ps1 run.
#
# Columns (pipe-delimited):
#   Status|ScriptVersion|ScanTimestamp|Endpoints|JavaProcesses|Frameworks|Loopback|Exposed|Candidates|RuntimeSec

$path = Join-Path $env:ProgramData 'ApiHarvest\summary.txt'

if (-not (Test-Path $path)) {
    Write-Output 'Not Run|||||||||'
    exit 0
}

$kv = @{}
foreach ($line in (Get-Content -Path $path -ErrorAction SilentlyContinue)) {
    if ($line -match '^([^=]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
}

$fields = @('Status','ScriptVersion','ScanTimestamp','Endpoints','JavaProcesses','Frameworks','Loopback','Exposed','Candidates','RuntimeSec')
Write-Output (($fields | ForEach-Object { if ($kv.ContainsKey($_)) { $kv[$_] } else { '' } }) -join '|')
