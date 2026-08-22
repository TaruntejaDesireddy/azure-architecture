# 32 · `windows/` — Endpoint KQL: `SecurityEvent` and `Syslog`

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)
![Tables](https://img.shields.io/badge/Tables-SecurityEvent%20·%20Syslog-0078D4?style=flat-square)

Endpoint telemetry, and the two very different shapes it arrives in.

This lab has exactly two endpoint log sources, and they behave nothing alike:

| Source | Table | What it is | Shape |
|---|---|---|---|
| Arc-connected Windows laptop | `SecurityEvent` | Windows Security event log, via AMA | **Parsed** — real columns per event field |
| `db-finance-prod01` (the honeypot host) | `Syslog` | Raw Linux syslog text | **Unparsed** — one free-text `SyslogMessage` column |

Everything below runs against `la-lab-eus-01`. Every query uses only tables and columns
this workspace actually has.

---

## ⚠️ Read this first — Sysmon has been down since 2026-08-07

**Sysmon on the Windows endpoint stopped producing events on 2026-08-07 and has not
been restarted.** Any query in this folder, or anywhere else, that depends on Sysmon
will return **zero rows** until that is fixed. Nothing is wrong with the query — the
data is not there.

Two things people get wrong about this:

**Sysmon does not land in `SecurityEvent`.** It lands in the `Event` table, under
`Source == "Microsoft-Windows-Sysmon"`. So a `SecurityEvent` query returning results
tells you nothing about whether Sysmon is healthy.

**`SecurityEvent` and Sysmon stopped at different times**, which is the whole reason
this is a real fault and not just "the laptop was off". If the machine had simply been
shut down, both channels would have stopped together.

Check the state yourself before assuming anything:

```kusto
// Sysmon health. Expect ZERO rows today - this is the outage, not a broken query.
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize Records = count(), Latest = max(TimeGenerated) by EventID
| order by Records desc
```

> **There is a deadline on this.** Workspace retention is **30 days**. The historical
> Sysmon rows from before 2026-08-07 age out of the workspace in early September 2026.
> Once they do, there is nothing left to diagnose against — only a table that has always
> been empty as far as any query can see.

What is lost while it is down: process injection (`CreateRemoteThread`), WMI persistence,
DNS queries attributed to a process, registry persistence, and full command lines with
parent attribution. `SecurityEvent` covers **none** of those, which is why the sections
below stop where they stop.

---

## 🪟 `SecurityEvent` — the Windows endpoint

One caveat that shapes every query here: the Data Collection Rule for this endpoint
collects the **Security** channel and the Sysmon Operational channel. It does **not**
collect the **System** or **Application** channels. If an event ID you expect lives in
System (7045 service install, 7034 service crash, 6005/6006 boot), it is not in this
workspace at all — not filtered out, never collected.

### 1. Is the table alive, and what is actually in it?

Always the first query in an unfamiliar workspace, and the first thing to run when a
detection mysteriously stops firing. It answers "do I have data, is it current, and
which event IDs am I actually receiving" in one pass.

```kusto
SecurityEvent
| where TimeGenerated > ago(30d)          // 30d is the full retention window - no point going wider
| summarize Events = count(), Latest = max(TimeGenerated) by EventID, Activity
| order by Events desc
```

A `Latest` value that is hours or days stale on a live endpoint means the pipeline
stopped. That is a different problem from a query returning nothing, and worth separating
before you start rewriting KQL.

### 2. Logon types — and what 3, 4, 5 and 10 actually mean

Event **4624** is a successful logon. On its own that is close to useless; the
`LogonType` is what carries the meaning. The same event ID covers someone sitting at the
keyboard and someone authenticating from across the network, and conflating them is how
you end up with a detection that fires on every scheduled task.

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where TargetUserName !endswith "$"      // machine accounts ($) are constant background noise
| extend LogonKind = case(
    LogonType == 2,  "2 - Interactive (at the keyboard)",
    LogonType == 3,  "3 - Network (SMB, file share, remote WMI)",
    LogonType == 4,  "4 - Batch (scheduled task)",
    LogonType == 5,  "5 - Service (a service starting under an account)",
    LogonType == 7,  "7 - Unlock (workstation unlocked)",
    LogonType == 8,  "8 - NetworkCleartext (password sent in the clear)",
    LogonType == 9,  "9 - NewCredentials (runas /netonly)",
    LogonType == 10, "10 - RemoteInteractive (RDP)",
    LogonType == 11, "11 - CachedInteractive (cached creds, no DC reachable)",
    strcat("Other - ", tostring(LogonType)))
| summarize Logons = count(), Accounts = dcount(TargetUserName), Latest = max(TimeGenerated)
    by LogonKind
| order by Logons desc
```

The four that matter most:

| Type | Name | What it means in practice | Why an analyst cares |
|---:|---|---|---|
| **3** | Network | Authenticated from the network — file share, SMB, remote WMI, admin share | The workhorse of **lateral movement**. Also the noisiest legitimate type, so threshold carefully |
| **4** | Batch | A scheduled task ran under an account | A task suddenly running under a *user* account, not a service account, is worth a look — it is a common persistence landing spot |
| **5** | Service | A service started under an account | Near-constant at boot and mostly benign. A **new** account appearing as type 5 usually means a service was installed — cross-check §7 |
| **10** | RemoteInteractive | RDP | A full interactive desktop session from elsewhere. On a single-user laptop, an unexpected type 10 is one of the highest-signal events available |

Type **2** vs type **10** is the distinction people miss: both give a real desktop, but
type 2 requires physical presence and type 10 does not.

### 3. Failed logons, grouped by *why* they failed

Event **4625**. Counting raw failures tells you volume; the `SubStatus` code tells you
what the attacker knows. "Bad password" means the account name is real and they are
guessing the password. "No such user" means they are guessing names. Those are different
stages of an attack and deserve different responses.

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| extend Reason = case(
    SubStatus == "0xc000006a", "Bad password - THE ACCOUNT EXISTS",
    SubStatus == "0xc0000064", "No such user - name guessing",
    SubStatus == "0xc0000072", "Account is disabled",
    SubStatus == "0xc0000234", "Account is locked out",
    SubStatus == "0xc0000070", "Blocked by workstation restriction",
    SubStatus == "0xc0000193", "Account expired",
    SubStatus == "0xc000006f", "Outside permitted logon hours",
    strcat("Other - ", SubStatus))
| summarize Failures = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by TargetUserName, IpAddress, Reason, LogonType
| order by Failures desc
```

Two things to know before you trust the output. `IpAddress` is `-` for logons that never
crossed the network (console, some service logons) — that is normal, not missing data.
And if every row lands in the `Other` bucket, the hex codes are not being emitted in the
case you expect; confirm with `SecurityEvent | where EventID == 4625 | distinct SubStatus`
rather than guessing.

### 4. Failures followed by a success — the pattern, not the count

A brute force that fails forever is noise. A brute force that **succeeds** is an incident.
This is the query that separates them: same account, same source IP, a burst of failures,
then a logon that worked.

The join here is doing real work — it is correlating two different event IDs across a
time window, which a single `summarize` cannot express.

```kusto
let window = 1h;
let lookback = 7d;
let failures =
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4625
    | where TargetUserName !endswith "$"
    | where isnotempty(IpAddress) and IpAddress != "-"     // network-sourced attempts only
    | summarize Failures = count(), FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated)
        by TargetUserName, IpAddress, bin(TimeGenerated, window)
    | where Failures >= 5;                                  // re-baseline this per environment
let successes =
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4624
    | where LogonType in (3, 10)                            // network or RDP - not console, not service
    | project SuccessTime = TimeGenerated, TargetUserName, IpAddress, LogonType;
failures
| join kind=inner successes on TargetUserName, IpAddress
// The success must land inside or just after the failure burst, not days later
| where SuccessTime between (FirstFail .. LastFail + window)
| project FirstFail, LastFail, SuccessTime, TargetUserName, IpAddress, LogonType, Failures
| order by SuccessTime desc
```

`Failures >= 5` is a lab threshold for a quiet, single-user machine. It is not a number to
carry to a client tenant unchanged.

### 5. Process creation — 4688

Event **4688** is the closest `SecurityEvent` gets to EDR, and it is a poor substitute for
Sysmon Event 1. The filter below targets the interpreters and signed-binary proxies that
attackers reach for, rather than dumping every process the machine ever ran.

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where NewProcessName has_any (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe")
| project TimeGenerated, Computer,
          Actor  = SubjectUserName,
          Parent = ParentProcessName,      // the parent is usually more suspicious than the child
          Child  = NewProcessName,
          CommandLine,
          TokenElevationType               // %%1936 = full admin token, %%1937 = elevated, %%1938 = limited
| order by TimeGenerated desc
```

**Two things will bite you here.** 4688 is only written if the *Audit Process Creation*
policy is enabled — it is off by default on Windows. And `CommandLine` is populated only
if the separate *Include command line in process creation events* policy is also enabled.
An empty `CommandLine` column across the board means that second policy is off, and a
4688-based detection is worth roughly nothing without it.

This is the specific gap Sysmon Event 1 fills: full command line, parent attribution and
image hashes, without depending on two audit policies being set correctly.

### 6. Account changes — creation, enablement, resets, group adds

Persistence and privilege escalation both leave marks here. Grouping the whole account
lifecycle into one query is better than seven separate ones, because the *sequence* is the
signal: an account created, then added to a group, then logged on with, inside ten minutes.

```kusto
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (4720, 4722, 4723, 4724, 4725, 4726, 4738, 4728, 4732, 4756)
| extend Change = case(
    EventID == 4720, "Account CREATED",
    EventID == 4722, "Account enabled",
    EventID == 4723, "Password change attempted (by the user themselves)",
    EventID == 4724, "Password RESET attempted (by someone else - admin action)",
    EventID == 4725, "Account disabled",
    EventID == 4726, "Account DELETED",
    EventID == 4738, "Account properties changed",
    EventID == 4728, "Member added to a global group",
    EventID == 4732, "Member added to a LOCAL group",
    EventID == 4756, "Member added to a universal group",
    strcat("Unmapped - ", tostring(EventID)))
| project TimeGenerated, Computer, Change,
          Actor  = SubjectUserName,        // who did it
          Target = TargetUserName,         // on the group-add events this is the GROUP name
          Member = MemberName              // and this is who was added
| order by TimeGenerated desc
```

Watch the column meanings on the group events — **4732** puts the *group* in
`TargetUserName` and the *added member* in `MemberName`. Reading it the other way round
produces a confident, wrong conclusion. 4732 on a local machine is the one to care about
most: it is how an attacker gets into local Administrators.

The pairing worth internalising is **4723 vs 4724**. 4723 is a user changing their own
password. 4724 is somebody resetting *another* account's password — an admin action, and a
straightforward account takeover if the actor should not have done it.

### 7. Service installs

A service is a durable, boots-with-the-machine persistence mechanism, and installing one
usually requires the privilege an attacker just worked to get.

```kusto
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4697                    // "A service was installed in the system"
| project TimeGenerated, Computer,
          Actor = SubjectUserName,
          ServiceName, ServiceFileName,    // ServiceFileName is the binary path - the interesting field
          ServiceType, ServiceStartType, ServiceAccount
| order by TimeGenerated desc
```

**If this returns nothing, it is probably not an attacker-free machine.** Event 4697 lives
in the Security channel but requires the *Audit Security System Extension* subcategory,
which is **off by default**. Confirm with `SecurityEvent | where EventID == 4697 | count`
before treating an empty result as a clean bill of health.

And the event most tutorials reach for, **7045**, is in the **System** channel — which this
lab's DCR does not collect. It will never appear here regardless of audit policy. Enable
the 4697 subcategory, or add the System channel to the DCR and accept the extra ingestion.

---

## 🐧 `Syslog` — the honeypot host

`Syslog` on `db-finance-prod01` collects facilities `local0`, `local1`, `kern`, `daemon`,
`auth` and `authpriv`. Everything arrives as one free-text `SyslogMessage` column plus a
little envelope metadata: `Facility`, `ProcessName`, `SeverityLevel`, `Computer`.

### 8. What is actually talking, and on which facility

Run this before writing any `Syslog` query. On this host in particular, the answer is not
what you would guess.

```kusto
Syslog
| where TimeGenerated > ago(24h)
| summarize Rows = count(), Latest = max(TimeGenerated) by Computer, Facility, ProcessName
| order by Rows desc
```

**Here is the trap, and it is specific to this host.** `ProcessName == "sshd"` matches
**two completely different things**:

| Facility | What `sshd` actually is | Meaning of a failed login |
|---|---|---|
| `local0` | The **decoy shell** on port 22/2222. Deliberately identifies as `sshd`, never as the software's real name | Hostile by definition. Nobody legitimate is there |
| `auth` / `authpriv` | The **real OpenSSH daemon** on port 2200 — the operator's actual admin access | Could be the operator fat-fingering a key. Could be far worse |

A query that filters on `ProcessName == "sshd"` alone silently merges the operator's own
admin sessions with attacker traffic. **Always constrain the facility.**

### 9. Authentication failures against the real admin daemon

Scoped deliberately to `auth`/`authpriv`, so this is about the operator's genuine SSH
service and not the decoy.

```kusto
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")   // the REAL sshd on 2200 - see the table above
| where ProcessName == "sshd"
| where SyslogMessage has_any (
    "Failed password", "Invalid user", "authentication failure", "Connection closed by authenticating user")
| project TimeGenerated, Computer, ProcessName, SeverityLevel, SyslogMessage
| order by TimeGenerated desc
```

Now the version that tries to turn that text into fields — and demonstrates exactly why
this approach is not used for detection here:

```kusto
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv") and ProcessName == "sshd"
| where SyslogMessage startswith "Failed password"
// Brittle BY CONSTRUCTION: this is coupled to OpenSSH's exact wording.
| parse SyslogMessage with * "Failed password for " User:string " from " SrcIP:string " port " *
| summarize Attempts = count() by User, SrcIP
| order by Attempts desc
```

Look at what `User` comes back as. OpenSSH writes `Failed password for root ...` for a real
account but `Failed password for invalid user root ...` for one that does not exist — so
the same parse yields `root` in one case and `invalid user root` in the other. Two rows,
one actual username, and a `dcount(User)` that is quietly wrong. Nothing errored. That is
the failure mode: **it does not break loudly, it breaks silently and keeps reporting
success.**

### 10. `sudo` — privilege escalation on the host

`sudo` logs to `authpriv`. Both the successful commands and the refusals matter, so
classify rather than filter.

```kusto
Syslog
| where TimeGenerated > ago(7d)
| where ProcessName == "sudo"
| extend Kind = case(
    SyslogMessage has "user NOT in sudoers",         "DENIED - not in sudoers",
    SyslogMessage has "incorrect password attempts", "DENIED - wrong password",
    SyslogMessage has "authentication failure",      "DENIED - auth failure",
    SyslogMessage has "COMMAND=",                    "Command executed",
    "Other")
| summarize Events = count(), Latest = max(TimeGenerated) by Kind, Computer
| order by Events desc
```

`user NOT in sudoers` is the high-signal one. A legitimate operator knows whether they have
sudo; an attacker who has landed on the box is finding out.

To read the individual commands, swap the `summarize` for
`| where Kind == "Command executed" | project TimeGenerated, SyslogMessage | order by TimeGenerated desc`.
The `COMMAND=` portion of the message carries the full command line.

---

## 🚫 Why this lab's detections query `CommonSecurityLog`, not `Syslog`

`Syslog` and `CommonSecurityLog` come from **the same host**. The difference is where the
parsing happens.

An earlier iteration of this lab's ruleset scraped raw `Syslog` rows with regular
expressions, pulling source IP, username, password and session ID out of a single
`SyslogMessage` string. It worked. It was also coupled to the exact wording of log lines
produced by software the lab does not control — and as §9 shows, a wording change does not
raise an error. The rule keeps running, keeps reporting success, and matches nothing. A
detection that fails silently is worse than no detection, because it also produces
confidence.

So the honeypot's sensors emit **CEF on facility `local4`**, which lands in
`CommonSecurityLog` as named columns. Parsing happens **once, at ingestion**, in code the
lab owns and can test — instead of once per rule, in a regex nobody revisits.

Same event as §9, from the decoy shell, without a regex anywhere:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor in ("sshd", "telnetd")           // the decoy shell, deliberately not named after the software
| where DeviceEventClassID == "login.failed"
| summarize Attempts    = count(),
            Usernames   = dcount(DestinationUserName),
            Passwords   = dcount(DeviceCustomString2), // DeviceCustomString2 = the password that was tried
            First       = min(TimeGenerated),
            Last        = max(TimeGenerated)
    by SourceIP
| where Attempts >= 10
| order by Attempts desc
```

`SourceIP`, `DestinationUserName` and `DeviceEventClassID` are real columns. Nothing here
depends on a sentence staying phrased the way it is phrased today.

| | `Syslog` | `CommonSecurityLog` |
|---|---|---|
| Shape | One free-text `SyslogMessage` | Named, typed columns |
| Parsing | Per query, by you | Once, at ingestion |
| Fails by | Silently returning nothing | Loudly — a missing column errors |
| Entity mapping in a rule | Only after a successful parse | Direct from the column |
| Used for | **Investigation** — the safety net when CEF breaks | **Detection** — all deployed rules |

`Syslog` is kept deliberately, and it earns its place: when the CEF pipeline breaks,
`Syslog` is usually the only source that shows you *why*. That is an operational role, not
a detection one.

The **38 deployed analytics rules** query `CommonSecurityLog`, `SigninLogs`, `AuditLogs`,
`AzureActivity` and `AppServiceHTTPLogs`. None regex-scrape `Syslog`. There is currently no
endpoint detection category at all — see the
[detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).
That gap is a direct consequence of the Sysmon outage at the top of this page.

---

## 💰 Cost — what these queries do and do not cost

Running a query is free. **You already paid when the rows were ingested**, and on a
$15/month budget that distinction is the whole game: explore as much as you like, ingest
carelessly once and you have a problem.

What genuinely matters here:

| Practice | Why |
|---|---|
| Always bound `TimeGenerated` | An unbounded query on `Syslog` or `SecurityEvent` scans everything retained. Slow, and it trains a bad habit that does cost money at scale |
| Never go past `ago(30d)` | Retention is 30 days. `ago(90d)` is not expensive, it is simply empty — and reads as a broken query |
| Filter before you `summarize` | Push `where` as early as possible. `has` beats `contains`; `contains` scans substrings |
| Avoid bare `search *` | It touches every table in the workspace. Fine once when you are lost, terrible as a habit |
| Watch the daily cap | The workspace cap is a **shared** resource. Breaching it stops ingestion for *every* source, honeypot included — a verbose Sysmon config on the laptop can blind the internet-facing host |

That last row is the one to actually remember, and it is the reason the Sysmon fix must
come with a **filtered** config rather than the default.

```kusto
// Where the ingestion budget is actually going. Run this weekly.
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize GB = round(sum(Quantity) / 1024, 4) by DataType
| order by GB desc
```

---

## 🧭 Where to go next

| Want to | Go to |
|---|---|
| The honeypot's CEF schema in full | [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md) — honeypot category |
| Workspace, tables, scope and cost | [Logs guide](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/04-logs.md) |
| Turning a query into a rule | [Hunting guide](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/08-hunting.md) |
| Paced KQL practice | [SOC-L1 Part 02](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/SOC-L1-PATH/part-02.md) |

**Before anything else in this folder: restart Sysmon.** Every query above is written
against data that exists today. The queries worth writing next are not, and will not be
until the endpoint is producing Event 1 again.

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Roadmap](../../README.md)
