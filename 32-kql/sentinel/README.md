# 32 — KQL · `sentinel/`

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Table](https://img.shields.io/badge/Table-CommonSecurityLog-0078D4?style=flat-square)
![Queries](https://img.shields.io/badge/Queries-13-0078D4?style=flat-square)

> A working query library for the honeypot's CEF feed in workspace `la-lab-eus-01`.
> Every query below is written against columns this lab actually populates — no
> sample-data tables, no columns borrowed from someone else's connector.

## 🧭 Why this table, and not the others

The lab workspace has plenty of tables with data in them — `SigninLogs`, `AzureActivity`,
`SecurityEvent`, `StorageBlobLogs`, `AppServiceHTTPLogs`. `CommonSecurityLog` is the one
worth building a library around, for three reasons:

- **It is the only table here fed by an internet-facing sensor taking real attacker traffic.**
  Everything else records what *you* did in your own tenant. This records what strangers did to you.
- **It carries three independent sensors in one schema.** Host firewall, network IDS/IPS, and
  the application shell all land in the same table with the same column names, which is what
  makes genuine cross-source correlation possible in a single query instead of a data-export job.
- **It is already parsed.** The three converters on the host do the string-mangling once and hand
  Sentinel typed columns. `Syslog` holds the same events as raw text — keep it for investigation
  when you need the untouched line, but do not write detections against it.

> [!NOTE]
> `SecurityEvent` is also live, from an Arc-connected laptop — but Sysmon on that host has been
> down since **2026-08-07**, so process-creation coverage there is incomplete. Do not treat an
> empty `SecurityEvent` result as evidence that nothing happened.

## 📇 The schema contract these queries are written against

Read this table before writing anything. Every query below depends on it.

| Column | `sshd` / `telnetd` (Door 4) | `Suricata` (Door 3) | `nftables` (Door 2) |
|---|---|---|---|
| `DeviceVendor` | `sshd` or `telnetd` | `Suricata` | `nftables` |
| `DeviceEventClassID` | `session.connect`, `login.failed`, `login.success`, `command.input`, `session.file_download`, `session.file_upload` | `gid:signature_id`, e.g. `1:2024897` | `ALLOW-SVC`, `DENY-SENSITIVE` |
| `DeviceEventCategory` | `Door 4 - Application Shell (SSH)` | `Door 3 - Network IDS/IPS - <cat>` | `Door 2 - Host Firewall` |
| `DeviceAction` | `Allowed` / `Denied` | `Allowed` / `Denied` | `Allowed` / `Denied` |
| `Activity` | human-readable event name | Suricata signature name | human-readable event name |
| `DeviceCustomString1` | **session id** | **priority** | **interface** |
| `DeviceCustomString2` | password tried | — | — |
| `DeviceCustomString3` | command typed | — | — |
| `DestinationUserName` | username tried | — | — |
| `LogSeverity` | CEF severity, **as a string** | CEF severity, **as a string** | CEF severity, **as a string** |

`SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `Protocol` and
`Computer` (always `db-finance-prod01`) are populated across all three.

### Three traps that will silently return the wrong answer

> [!IMPORTANT]
> **1. `DeviceCustomString1` means three different things.** It is a session id from the shell,
> a Suricata priority number, and a network interface name from the firewall — in the same column.
> A query that reads `DeviceCustomString1` without filtering `DeviceVendor` will happily mix
> session identifiers with the number `2`, return rows, and look like it worked. **Always constrain
> the vendor when you touch a custom string.** `DeviceCustomString1Label` is the built-in column
> that carries the CEF label for cs1 — if these converters set it, it names which meaning you got,
> so check that it is populated before leaning on it.
>
> **2. `LogSeverity` is a string, not a number.** `LogSeverity > 6` does not quietly return the
> wrong rows — it fails outright, because KQL will not compare a `string` to a `long`. Quote the
> number to make it run (`LogSeverity > "6"`) and you get a *lexical* comparison instead: `"9"`
> sorts above `"6"`, but `"10"` sorts *below* it, so the highest severity vanishes from the result.
> Convert, then compare: `toint(LogSeverity) >= 6`.
>
> **3. The app-layer vendor is not always `sshd`.** The fake shell answers Telnet too, and those
> rows carry `DeviceVendor == "telnetd"`. `where DeviceVendor == "sshd"` quietly drops them. Use
> `in ("sshd", "telnetd")` unless you specifically want one protocol.

> [!NOTE]
> `DeviceEventCategory` (the Door label) was added to the converters on **2026-08-22**. Rows
> ingested before that are empty in this column — which matters, because workspace retention is
> 30 days and older rows are still in range. Filter on `DeviceVendor` when you need the full
> window; use `DeviceEventCategory` when you want the readable label.

---

## 🔎 The query library

Each query says what it answers before it shows how. Run them in **Logs**, scoped to the
workspace, and change `ago()` to suit — the windows below are starting points, not requirements.

### 1. What is actually arriving, by sensor

**Answers:** is every sensor still shipping, and what mix of events is coming in right now?

This is the query to run first, every time, before you trust any other result. If a vendor you
expect is missing from the output, the problem is the pipeline, not the attackers. It is also the
cheapest way to learn the shape of the data — one scan, everything summarised.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)          // bound the window before anything else
| summarize Events    = count(),
            Example   = any(Activity),    // any() is cheap; take() semantics, not a sort
            FirstSeen = min(TimeGenerated),
            LastSeen  = max(TimeGenerated)
        by DeviceVendor, DeviceProduct, DeviceEventClassID, DeviceAction
| order by Events desc
```

### 2. Which door did the traffic reach

**Answers:** how far into the stack did each source get — blocked at the firewall, caught by the
IDS, or all the way to a shell prompt?

The Door labels encode the sensor's position in the traffic path, so this is a depth-of-penetration
view rather than a volume view. A source appearing only at Door 2 was stopped early; a source
appearing at Door 4 got to type commands.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(DeviceEventCategory)   // pre-2026-08-22 rows have no label - see the note above
| summarize Events        = count(),
            DistinctHosts = dcount(SourceIP)
        by DoorReached = DeviceEventCategory, DeviceAction
| order by DoorReached asc, Events desc
```

### 3. Brute force, by source IP

**Answers:** who is guessing credentials, how hard, and what *shape* is the guessing?

The count alone is not the interesting part. The ratio of distinct usernames to distinct passwords
tells you what kind of tool you are looking at, and that changes the response. A spray across many
accounts with three common passwords is a different problem from one account hammered with ten
thousand.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "login.failed"
| summarize FailedAttempts    = count(),
            DistinctUsers     = dcount(DestinationUserName),
            DistinctPasswords = dcount(DeviceCustomString2),
            UsernamesTried    = make_set(DestinationUserName, 20),
            FirstAttempt      = min(TimeGenerated),
            LastAttempt       = max(TimeGenerated)
        by AttackerIP = SourceIP
| where FailedAttempts >= 5               // filtering an aggregate, so this belongs after summarize
| extend AttackDurationSeconds = datetime_diff('second', LastAttempt, FirstAttempt)
// the user:password ratio is what distinguishes the tool being used
| extend Shape = case(
        DistinctUsers >= 10 and DistinctPasswords <= 3,  "Spray - many accounts, few passwords",
        DistinctUsers <= 2  and DistinctPasswords >= 10, "Targeted - one account, many passwords",
        "Dictionary sweep")
| order by FailedAttempts desc
```

### 4. Successful logins

**Answers:** did anyone get in, with what credential, and under which session id?

On a normal server a successful login is a routine event needing triage. On this host it is not:
nobody legitimate works here, so every success on the fake shell was guessed or stolen. Capture
the session id from this result — it is the join key for queries 6 through 9.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "login.success"
| project TimeGenerated,
          Computer,
          AttackerIP   = SourceIP,
          Protocol     = DeviceVendor,          // sshd vs telnetd tells you which service answered
          Username     = DestinationUserName,
          PasswordUsed = DeviceCustomString2,
          SessionId    = DeviceCustomString1,
          Activity
| order by TimeGenerated desc
```

### 5. Which credential pairs actually work

**Answers:** what is in the wild credential lists that real tooling is carrying right now?

This is one of the few genuinely novel outputs a small honeypot produces. The failed attempts are
noise you can get anywhere; the pairs that *succeed* against this host tell you what the current
generation of scanners believes is worth trying. Useful as password-blocklist input, and a good
concrete artefact to show a trainee.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)          // full retention window - see the cost note below
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "login.success"
| summarize Successes      = count(),
            DistinctSources = dcount(SourceIP),
            FirstSeen      = min(TimeGenerated)
        by Username = DestinationUserName, PasswordUsed = DeviceCustomString2
| order by Successes desc
```

### 6. Reconstruct one session, in order

**Answers:** what did this specific actor do, from connect to last command, as a timeline?

This is the investigation query — the one you run after an incident opens. Do not summarise here;
you want every row in sequence, because the *order* is the evidence. Enumerate, then hunt for
credentials, then try to pull a payload is a completely different story from three random commands.

```kusto
let TargetSession = "aa11bb22";           // paste the SessionId from query 4
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("sshd", "telnetd")   // MUST come first - cs1 is only a session id here
| where DeviceCustomString1 == TargetSession
| project TimeGenerated,
          Event    = DeviceEventClassID,
          Activity,
          SourceIP,
          Username = DestinationUserName,
          Password = DeviceCustomString2,
          Command  = DeviceCustomString3
| order by TimeGenerated asc
```

### 7. Busiest command sessions

**Answers:** which sessions are worth reading in full, ranked by how much the actor actually typed?

A session with forty commands is a human or a capable script; a session with one is a bot checking
the door. Use this to pick which session ids to feed into query 6, rather than reading them all.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "command.input"
| summarize CommandCount = count(),
            Commands     = make_list(DeviceCustomString3, 50),
            SessionStart = min(TimeGenerated),
            SessionEnd   = max(TimeGenerated)
        by SessionId = DeviceCustomString1, AttackerIP = SourceIP
| extend SessionSeconds = datetime_diff('second', SessionEnd, SessionStart)
| order by CommandCount desc
```

> [!WARNING]
> `make_list` is not a guaranteed ordering. It is fine for eyeballing what a session touched, but
> if the sequence matters to your conclusion, go back to query 6 and read the real timeline.

### 8. Credential-file access

**Answers:** did the actor go looking for something to escalate with or exfiltrate?

Reaching for a specific credential file is not browsing — it is intent. This host is seeded with a
known set of bait files, so a hit here means the actor moved from "I have a shell" to "I want
something out of it". `has_any` is deliberate: it is index-assisted and much cheaper than the
equivalent chain of `contains`.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any (
        ".ssh/id_rsa", ".aws/credentials", "/opt/app/.env", ".bash_history", "finance_prod")
| extend FileTargeted = case(
        DeviceCustomString3 has ".ssh/id_rsa",      "SSH private key",
        DeviceCustomString3 has ".aws/credentials", "Cloud credentials",
        DeviceCustomString3 has "/opt/app/.env",    "Application config",
        DeviceCustomString3 has "finance_prod",     "Database backup archive",
        DeviceCustomString3 has ".bash_history",    "Shell history",
        "Unknown")
| project TimeGenerated, Computer,
          AttackerIP = SourceIP,
          SessionId  = DeviceCustomString1,
          FileTargeted,
          Command    = DeviceCustomString3
| order by TimeGenerated desc
```

### 9. Outbound download attempts

**Answers:** did the actor try to pull a second-stage payload in, and from where?

The URL is the prize here — a live, actor-controlled indicator harvested from a real attack rather
than copied out of a blog post. Two signals are combined on purpose, and they are not redundant:
`command.input` catches the *attempt* even when the transfer never completed, while
`session.file_download` fires when the shell actually handled a transfer.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID in ("command.input", "session.file_download", "session.file_upload")
// a download shows up either as a fetch command, or as a transfer event
| where DeviceEventClassID != "command.input"
     or DeviceCustomString3 has_any ("wget", "curl", "tftp", "nc ", "scp")
| extend DownloadUrl = extract(@"(https?://[^\s]+)", 1, DeviceCustomString3)
| project TimeGenerated, Computer,
          AttackerIP = SourceIP,
          SessionId  = DeviceCustomString1,
          Event      = DeviceEventClassID,
          Command    = DeviceCustomString3,
          DownloadUrl
| order by TimeGenerated desc
```

> [!CAUTION]
> On `session.file_download` / `session.file_upload` rows the command column is empty — the URL
> arrives on the transfer event itself (the converter sends it as CEF `request=`, which lands in
> `RequestURL`). If `DownloadUrl` comes back blank on those rows, add `RequestURL` to the
> `project` list and check there. And do not open any URL this returns from a normal browser.

### 10. Port scans, from the firewall

**Answers:** who is sweeping ports this host deliberately does not serve?

`DENY-SENSITIVE` is a purpose-built firewall rule covering ports the host has no business
answering — telnet, SMB, RDP, and the database ports. Legitimate traffic never touches them, so a
source hitting several in sequence is a sweep, and `DeviceAction == "Denied"` confirms it was
actually dropped rather than merely observed.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "nftables"
| where DeviceEventClassID == "DENY-SENSITIVE"
| summarize ProbeCount    = count(),
            DistinctPorts = dcount(DestinationPort),
            PortsProbed   = make_set(DestinationPort, 30),
            Interface     = any(DeviceCustomString1),   // cs1 = interface for THIS vendor only
            FirstSeen     = min(TimeGenerated),
            LastSeen      = max(TimeGenerated)
        by SourceIP, Computer
| where DistinctPorts >= 5
| extend ScanDurationSeconds = datetime_diff('second', LastSeen, FirstSeen)
| order by DistinctPorts desc
```

> [!NOTE]
> An empty result here is not necessarily a quiet day. The Azure NSG in front of this VM permits
> only inbound TCP/22, so probes to those sensitive ports can be dropped upstream and never reach
> the host firewall at all — no packet, no log line, no row. If you get nothing, swap
> `DENY-SENSITIVE` for `ALLOW-SVC` to see what the firewall *is* recording.

### 11. Suricata high-severity signatures

**Answers:** what known-bad content patterns matched, and did the inline IPS stop them?

The converter maps Suricata priority 1/2/3 to CEF severity 9/6/3, which is why
`toint(LogSeverity) >= 6` means precisely "priority 1 or 2" — exploit attempts and attack
responses — while excluding the priority-3 informational bulk that would otherwise dominate.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| where toint(LogSeverity) >= 6           // string column - toint() first, or "10" sorts below "6"
| where isnotempty(Activity)
| extend Priority = DeviceCustomString1    // cs1 = Suricata priority here, NOT a session id
| project TimeGenerated, Computer,
          SignatureId   = DeviceEventClassID,   // "gid:sid", e.g. "1:2024897"
          SignatureName = Activity,
          Priority, SourceIP, DestinationIP, DestinationPort, Protocol,
          Blocked = DeviceAction               // "Denied" = the IPS actually dropped it
| order by TimeGenerated desc
```

> [!IMPORTANT]
> A signature match is not proof of compromise. `Allowed` means it was detected and passed
> through — go confirm with the session data whether the actor got anywhere. Read the direction of
> travel too: external → this host is an inbound attack, this host → external is a compromise
> indicator and a much worse finding.

### 12. Cross-source correlation — one IP, two independent layers

**Answers:** which sources were seen by *both* the network layer and the application layer?

This is the most valuable query in the library, and the reason the honeypot is worth its cost.
Most internet background noise is single-protocol — a scanner touches port 22 or it touches
port 443, rarely both, and rarely does a scanner come back to interact. An IP that appears at the
network layer *and* opens a shell session is a full attack progression: find the host, then try to
get in. Two independent evidence sources, one narrative.

The complexity here is doing real work: the two `let` blocks summarise each layer down to one row
per IP *before* the join, so the join operates on a small set rather than raw event rows.

```kusto
let lookback = 24h;
let networkLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DeviceVendor in ("Suricata", "nftables")     // Doors 2 and 3
    | where isnotempty(SourceIP)
    | summarize NetworkEvents     = count(),
                NetworkSignals    = make_set(Activity, 8),
                FirstNetworkSeen  = min(TimeGenerated)
            by SourceIP;
let appLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DeviceVendor in ("sshd", "telnetd")          // Door 4
    | where isnotempty(SourceIP)
    | summarize AppEvents         = count(),
                AppEventTypes     = make_set(DeviceEventClassID, 8),
                FirstAppSeen      = min(TimeGenerated)
            by SourceIP;
networkLayer
| join kind=inner appLayer on SourceIP                   // inner join = seen by BOTH, by definition
| extend SecondsFromNetworkToApp =
        datetime_diff('second', FirstAppSeen, FirstNetworkSeen)
| project SourceIP, NetworkEvents, NetworkSignals, FirstNetworkSeen,
          AppEvents, AppEventTypes, FirstAppSeen, SecondsFromNetworkToApp
| order by AppEvents desc
```

Read `SecondsFromNetworkToApp` carefully. A gap of seconds suggests one automated tool doing both
steps. A gap of hours suggests scanning and exploitation were separate activities — possibly
separate operators working from a shared target list, which is a meaningfully different story.

### 13. One IP, every door — the pivot query

**Answers:** everything this table knows about a single address, in one timeline.

This is what you run when an incident names an IP and you need the whole picture fast. It crosses
all three sensors without a join, because they already share a schema — which is the payoff for
normalising to CEF on the host instead of parsing text per-query.

```kusto
let TargetIP = "203.0.113.10";            // replace with the IP from the incident
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where SourceIP == TargetIP              // equality on an indexed column - very cheap
| project TimeGenerated,
          Door       = DeviceEventCategory,
          Vendor     = DeviceVendor,
          Event      = DeviceEventClassID,
          Activity,
          Action     = DeviceAction,
          DestinationPort, Protocol,
          Username   = DestinationUserName,
          // cs2/cs3 are only meaningful on shell rows - blank elsewhere, by design
          Password   = DeviceCustomString2,
          Command    = DeviceCustomString3
| order by TimeGenerated asc
```

---

## 💰 Cost and efficiency

The lab runs on a hard **$15/month** budget, and workspace retention is **30 days**. Query cost is
not a theoretical concern here — an unbounded query against an internet-facing sensor's table is a
real way to lose a day's headroom.

| Habit | Why |
|---|---|
| `where TimeGenerated > ago(...)` as the **first** line | Lets the engine skip whole data shards. Every query above does this. |
| Filter `DeviceVendor` before custom strings | Correctness first, cost second — but it also narrows the scan. |
| `has` / `has_any` over `contains` | `has` matches whole terms and is index-assisted; `contains` is a substring scan. |
| `summarize` before `join` | Query 12 joins two small per-IP tables, not two streams of raw events. |
| `project` only what you will read | Fewer columns materialised, smaller result to render. |
| Never `search *` or `union *` | These touch every table in the workspace, including the noisy ones. |

Two specific warnings for this table:

- **Query 5 spans the full 30-day retention window** — deliberately, because credential lists are
  slow-moving. It is the most expensive query here. Run it occasionally, not on a schedule.
- **Do not remove the `ago()` bound from query 13 "just to be sure".** The honeypot is
  internet-facing and takes traffic continuously; a single busy source can hold a lot of rows.

## 🔗 Where these go next

Roughly half of these queries are the reading form of a rule that already runs on a schedule.
**38 analytics rules** are deployed in this workspace — the detection library, with each rule's
exported definition, severity, MITRE mapping and triage guidance, is at
[`DETECTIONS/README.md`](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).

Turning a hunting query into a detection is not a copy-paste. Ask three things first: does it
produce a finite number of rows per run, does every result need a human to look at it, and is the
threshold defensible? Query 1 fails all three — it is an orientation query and always will be.
Query 8 passes all three, which is why it is deployed.

## 🪜 Practice progression

Work through these rather than stopping at "the query ran":

| # | Stage | Done |
|--:|---|:--:|
| 1 | Run all 13 and read every column in the output | ☐ |
| 2 | Break one on purpose — drop the vendor filter from query 6 and explain the result | ☐ |
| 3 | Re-derive query 3's `Shape` logic from the raw rows without looking | ☐ |
| 4 | Write a 14th query this library is missing | ☐ |
| 5 | Promote one hunting query to a scheduled rule, with a defended threshold | ☐ |
| 6 | Cost-check it: estimate the daily scan before you enable it | ☐ |

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Roadmap](../../README.md)
