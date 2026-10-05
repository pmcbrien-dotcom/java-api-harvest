# Harvest-ApiInventory on Tanium

Three files:

| File | Role |
|---|---|
| `Harvest-ApiInventory.ps1` v5.3.0 | The scanner. Runs once per host via Tanium Deploy. |
| `Sensor-JavaApiHarvestResults.ps1` | Tanium sensor. Returns one row per discovered endpoint. |
| `Sensor-JavaApiHarvestSummary.ps1` | Tanium sensor. Returns one row per host (status, counts, runtime). |

The flow is: Deploy runs the scanner with `-TaniumOutput`, the scanner leaves
`results.txt` and `summary.txt` under `%ProgramData%\ApiHarvest\`, and the two
sensors read those files on demand. Nothing is pushed off-box; Tanium pulls.

---

## 1. Targeting — build the computer group first

Do not target the whole fleet. Only hosts with a JVM listening are worth a run.

**Interact → Ask a Question:**

```
Get Computer Name from all machines with Running Processes matches "(?i)^(java|javaw|tomcat\d*|prunsrv|wrapper)\.exe$"
```

Save the result as a **Computer Group** named `Java API Harvest Targets`. Tanium re-evaluates group membership continuously, so hosts that start or stop running Java move in and out on their own.

Refine as needed — a UAT-only group first (`and Computer Name contains "uat"` or your naming convention) for the pilot.

---

## 2. Package — Tanium Deploy

**Deploy → Packages → Create Package**

| Field | Value |
|---|---|
| Name | `Java API Harvest` |
| Content Set | whichever your Deploy packages live in |
| Files | upload `Harvest-ApiInventory.ps1` |
| Command | see below |
| Command timeout | **900** seconds (scanner's own hard stop is 600) |
| Run as | Local System (default) |

**Command (pilot — HEAD-only, safe):**

```
cmd /c powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Harvest-ApiInventory.ps1 -SafeProbeOnly -MaxRuntimeSec 600 -TaniumOutput "%ProgramData%\ApiHarvest" -OutputCsv "%ProgramData%\ApiHarvest\%COMPUTERNAME%.csv"
```

**Command (full — after the pilot validates):**

```
cmd /c powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Harvest-ApiInventory.ps1 -MaxRuntimeSec 600 -TaniumOutput "%ProgramData%\ApiHarvest" -OutputCsv "%ProgramData%\ApiHarvest\%COMPUTERNAME%.csv"
```

Why `cmd /c`: Tanium's package runner handles the `%ProgramData%` expansion through cmd reliably across Windows versions; direct `powershell.exe` invocation does not always expand it.

Why `-NonInteractive`: prevents any prompt from hanging the action.

Why Local System: the scanner reads other users' process command lines, the JDK `release` file, and Tomcat config under `Program Files`. A least-privilege service account works if it has local admin, but SYSTEM is the simplest and is Deploy's default.

**Verification (optional, recommended):** under the package's *Verification* tab add a query that checks the summary file was written in the last hour:

```
Get Java API Harvest Summary from all machines
```

with a verification condition of `Status equals Complete`. Deploy will then mark the action as verified per host.

**Exit code mapping:** the scanner exits 0 on any completed run, including partial. A non-zero exit means PowerShell itself failed to launch or parse the script — treat those as "investigate," not "retry."

---

## 3. Deployment — run it

**Deploy → Deployments → Create Deployment**

| Field | Value |
|---|---|
| Package | `Java API Harvest` |
| Targets | `Java API Harvest Targets` (or your UAT subset) |
| Deployment type | one-time for the pilot; recurring weekly for steady state |
| Distribute over | **4 hours** minimum for anything over 500 hosts |
| Concurrency | leave Tanium's default staggering on; do not set "run immediately on all" |
| Retry | 1 retry, 2-hour interval |
| Download timeout | default |

**Distribute over** is the fleet-safety control. 10,000 hosts over 4 hours is roughly 40 per minute, each running up to 10 minutes. That keeps the scanner's localhost probing spread out and avoids any shared infrastructure (DNS, domain controllers for WMI auth) seeing a burst.

For steady state, set a **recurring** deployment on a weekly schedule. Because the scanner's own mutex refuses a second instance, an overlapping run on a slow host simply exits.

---

## 4. Sensors — collect results

**Content → Sensors → New Sensor**, twice.

### Sensor A: `Java API Harvest Results`

| Field | Value |
|---|---|
| Name | `Java API Harvest Results` |
| Type | PowerShell |
| Result type | Text |
| Max age | 15 minutes |
| Column delimiter | `\|` |
| Columns | `Fqdn`, `Method`, `Path`, `Host`, `SpecHost`, `Framework`, `FrameworkVersion`, `Confidence`, `AppName`, `Port`, `Scheme`, `Exposure`, `Tls`, `CertNotAfter`, `HttpStatus`, `AuthChallenge`, `ServiceName`, `ProcessUser`, `JavaVersion`, `Sources` |
| Script | paste `Sensor-JavaApiHarvestResults.ps1` |

Twenty columns, pipe-delimited, matching the exact order the scanner writes. The sensor returns `Not Run` if no results file exists, `Stale` if it is older than a week, and `TRUNCATED` as a final row if a host has more than 5,000 endpoints (Tanium's per-endpoint result limit will bite well before that, so the cap is a safety net).

### Sensor B: `Java API Harvest Summary`

| Field | Value |
|---|---|
| Name | `Java API Harvest Summary` |
| Type | PowerShell |
| Result type | Text |
| Max age | 15 minutes |
| Column delimiter | `\|` |
| Columns | `Status`, `ScriptVersion`, `ScanTimestamp`, `Endpoints`, `JavaProcesses`, `Frameworks`, `Loopback`, `Exposed`, `Candidates`, `RuntimeSec` |
| Script | paste `Sensor-JavaApiHarvestSummary.ps1` |

One row per host. This is the one to check first after a deployment.

---

## 5. Questions — the report

**Immediately after a deployment, in Interact:**

```
Get Java API Harvest Summary from all machines with Computer Group equals "Java API Harvest Targets"
```

Sort by `Status`. Anything `Partial` hit the 600-second stop — look at `RuntimeSec` and `Endpoints` to see whether it was a genuinely huge host or a hung probe. Anything `Not Run` means Deploy didn't reach it.

**The inventory itself:**

```
Get Computer Name and Java API Harvest Results from all machines with Java API Harvest Summary:Status equals "Complete"
```

The result grid is the report. **Export → CSV** from the grid gives you the fleet file. Useful filters in the grid:

- `Exposure equals AllInterfaces` — reachable from the network
- `Confidence equals Confirmed` — framework identity is wire-verified
- `Sources contains ProcessDiscovery-Candidate` — guessed, not discovered
- `Tls equals False and Exposure not equals Loopback` — plaintext on an exposed port
- `AuthChallenge equals ""` and `HttpStatus equals 200` — answered without auth

**Framework rollup:**

```
Get Java API Harvest Results:Framework and Java API Harvest Results:FrameworkVersion from all machines
```

Tanium groups identical rows and counts them, so this gives you the framework/version distribution across the fleet in one question.

---

## 6. Recurring report — Tanium Connect

**Connect → Create Connection**

| Field | Value |
|---|---|
| Source | Saved Question |
| Saved Question | save the inventory question above as `Java API Inventory` |
| Destination | File (SMB share) / Splunk / SIEM / Email, as fits |
| Format | CSV |
| Schedule | weekly, a few hours after the recurring Deploy |

This gives you a standing weekly inventory landing somewhere outside Tanium without anyone running a question by hand. For the audit use case, the SMB-share CSV is probably what they want.

---

## 7. Pilot sequence

1. **Single host.** Run the scanner manually on one UAT box with `-DebugMode`. Confirm it parses under Windows PowerShell 5.1, finds what you expect, and the two output files appear.
2. **Sensors.** Create both sensors. Ask the Summary question against that one host. Confirm the row comes back and the columns line up.
3. **Deploy to UAT group.** `-SafeProbeOnly`, 1-hour distribution. Check Summary, then Results.
4. **Deploy to UAT group, full mode.** Compare endpoint counts against step 3 — the delta is what actuator and spec harvesting bought you.
5. **Deploy to production**, SafeProbeOnly first, 4-hour distribution, during a low-traffic window.
6. **Full mode in production** only for hosts where the SafeProbeOnly run showed a framework with introspection (`Frameworks contains SpringBoot`, say), targeted by a computer group built from the Summary sensor.

---

## 8. Safety summary for the change record

- Read-only. No configuration writes, no service restarts, no installs, no registry changes.
- Writes only to `%ProgramData%\ApiHarvest\` and `%TEMP%\Harvest-ApiInventory_*.log`.
- Network: HTTP HEAD/GET and TLS handshakes to ports on the local host only. No outbound off-box traffic.
- `-SafeProbeOnly` restricts to HEAD. Recommended for first production pass.
- Hard stop at `-MaxRuntimeSec` (600s). Partial results are still written and flagged.
- Single-instance mutex. Cannot run twice on one host.
- Filesystem walks are depth- and count-limited (`-SearchDepth 5`, `-MaxSpecFiles 10`).
- One WMI process query, one service query, one TCP enumeration per run.
- Command lines are never written to output unless `-IncludeCommandLine` is passed, and are credential-redacted even then.
- Certificate validation is bypassed for the scan's own localhost probes only, and only for the life of the process.
