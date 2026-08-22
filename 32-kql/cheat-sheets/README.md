# KQL Cheat Sheet — `la-lab-eus-01`

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Area](https://img.shields.io/badge/Area-cheat--sheets-0078D4?style=flat-square)
![Scope](https://img.shields.io/badge/Scope-this%20workspace%20only-0078D4?style=flat-square)

> **This is the page you keep open in a second tab.** Every query below is written against
> the real tables and real columns in `la-lab-eus-01` — no sample data, no invented columns.
> If a query here does not run, the workspace changed, not the cheat sheet.

Two standing constraints that shape every query on this page:

- **Retention is 30 days.** `ago(90d)` is not "slow", it is *empty*. There is nothing there.
- **Budget is $15/month.** Query cost is real. Sections marked 💸 explain where a habit
  actually costs money rather than just being untidy.

The 38 deployed analytics rules are the best worked examples of all of this —
[detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).

---

## 🗄️ Tables that actually have data

Everything else in the schema browser is an empty shell. Start here.

| Table | What it holds | Reach for it when |
|---|---|---|
| `CommonSecurityLog` | The honeypot's CEF feed — firewall, IDS/IPS, and fake shell, all three | Almost always. This is the richest table in the workspace |
| `Syslog` | Same host, raw unparsed text | Reconstructing a session line by line. **Investigation, not detection** |
| `SigninLogs` | Entra ID interactive sign-ins | Identity attacks, impossible travel, MFA failures |
| `AADNonInteractiveUserSignInLogs` | Token refreshes, background auth | The volume table — sign-in noise lives here |
| `AADServicePrincipalSignInLogs` | App/SPN authentication | Workload identity abuse |
| `AADManagedIdentitySignInLogs` | Managed identity auth | Resource-to-resource auth |
| `AuditLogs` | Entra directory changes | Who added the role, who created the app |
| `AzureActivity` | Subscription control plane | Who deployed/deleted/changed a resource |
| `SecurityEvent` | Windows events from an Arc-connected laptop | Logon events. ⚠️ Sysmon on it has been **down since 2026-08-07** |
| `StorageBlobLogs` | Blob read / write / delete | Data access and exfil questions |
| `Heartbeat` | Agent check-ins | "Did the sensor stop?" — always check this first |
| `Usage` | Ingestion volume by table | 💸 The bill. Check it before adding a data source |
| `AppServiceHTTPLogs` | The public decoy website | Web scanning, path probing, bad user agents |

---

## 🍯 `CommonSecurityLog` as *this lab* populates it

This is the important part of the page. Generic CEF documentation will not tell you this,
because these mappings are specific to the three converters running on `db-finance-prod01`.

There are **three sensors writing into one table.** Which columns are populated depends
entirely on `DeviceVendor`.

| Column | `sshd` / `telnetd` (fake shell) | `Suricata` (IDS/IPS) | `nftables` (host firewall) |
|---|---|---|---|
| `DeviceEventClassID` | `session.connect`, `login.failed`, `login.success`, `command.input`, `session.file_download`, `session.file_upload` | `gid:signature_id`, e.g. `1:2024897` | `ALLOW-SVC`, `DENY-SENSITIVE` |
| `DeviceEventCategory` | `Door 4 - Application Shell (SSH)` | `Door 3 - Network IDS/IPS - <cat>` | `Door 2 - Host Firewall` |
| `DeviceAction` | `Allowed` / `Denied` (login events only) | `Allowed` / `Denied` | `Allowed` / `Denied` |
| `DestinationUserName` | the username tried | — | — |
| `DeviceCustomString1` | **session id** | **priority** | **interface** |
| `DeviceCustomString2` | **the password tried** | — | — |
| `DeviceCustomString3` | **the command typed** | — | — |
| `Activity` | human-readable event name | Suricata signature name | human-readable event name |
| `Protocol` | — | populated | populated |

Always populated regardless of vendor: `TimeGenerated`, `SourceIP`, `DestinationIP`,
`SourcePort`, `DestinationPort`, `LogSeverity`, `Computer` (always `db-finance-prod01`).

> **`DeviceCustomString1` means three different things.** It is a session id, a Suricata
> priority, or a network interface depending on which sensor wrote the row. Never filter or
> group on it without pinning `DeviceVendor` first. This is the single most common way to
> produce a confidently wrong answer from this table.

**Why the vendor is `sshd` and not `Cowrie`:** the honeypot is disguised as a production
finance database server. Naming the software honestly in the log would tell any analyst
opening a raw row that the host is a decoy. Same reason the Door 4 label says
*Application Shell*, never *Honeypot*.

The one query that shows all three sensors side by side:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| project TimeGenerated, DoorReached = DeviceEventCategory, DeviceVendor,
          SourceIP, DestinationIP, Activity, DeviceAction
| order by TimeGenerated desc
```

---

## 🧱 The shape every query has

Learn the order, not the operators. Stages run top to bottom, each one narrowing what the
next one sees — so the cheap, high-selectivity filters go first.

```kusto
CommonSecurityLog                                  // 1. table
| where TimeGenerated > ago(24h)                   // 2. TIME FIRST, always
| where DeviceVendor == "sshd"                     // 3. narrow to one sensor
| where DeviceEventClassID == "login.failed"       // 4. narrow to one event
| extend Password = DeviceCustomString2            // 5. rename/compute
| summarize Attempts = count() by SourceIP         // 6. aggregate
| where Attempts > 50                              // 7. filter the aggregate
| order by Attempts desc                           // 8. sort
| take 20                                          // 9. limit
```

💸 Step 2 is not style. Log Analytics uses the `TimeGenerated` predicate to skip whole
data shards before it evaluates anything else. Move it to the bottom and the query still
returns the right answer — after scanning far more data than it needed to.

---

## 🔎 Filtering

| Operator | Does | Example |
|---|---|---|
| `where` | Keep rows matching a predicate | `where DeviceVendor == "Suricata"` |
| `where ... and ...` | Both must hold | `where DeviceVendor == "sshd" and DeviceEventClassID == "login.success"` |
| `in` | Value is in a list (case-sensitive) | `where DeviceVendor in ("Suricata", "nftables")` |
| `in~` | Same, case-insensitive | `where DeviceAction in~ ("denied", "DENIED")` |
| `!in` | Value is *not* in a list | `where DeviceEventClassID !in ("session.connect")` |
| `between` | Inclusive range, numbers or datetimes | `where DestinationPort between (1 .. 1024)` |
| `isnotempty` | Column has a value | `where isnotempty(DestinationUserName)` |
| `distinct` | Unique combinations of the listed columns | `distinct SourceIP, DestinationPort` |
| `take` / `limit` | Grab *some* rows — **not** the top ones | `take 10` |
| `top` | Grab the actual top N by a column | `top 10 by TimeGenerated desc` |

Separate `where` clauses read better than one long `and` chain, and cost the same — the
engine folds them together. Prefer three short lines over one long one.

**Two filters worth memorising for this workspace:**

Every failed shell login in the last day, newest first.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| project TimeGenerated, SourceIP, DestinationUserName,
          Password = DeviceCustomString2, SessionId = DeviceCustomString1
| order by TimeGenerated desc
```

Everything the host firewall dropped — these are attempts on the 8 sensitive ports
(Telnet/SMB/MSSQL/MySQL/RDP/PostgreSQL/Redis/MongoDB) that never reached a service.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor == "nftables" and DeviceEventClassID == "DENY-SENSITIVE"
| summarize Attempts = count() by SourceIP, DestinationPort
| order by Attempts desc
```

---

## ✂️ Selecting and shaping columns

`CommonSecurityLog` has dozens of columns and this lab populates a fraction of them.
Projecting is not cosmetic — it is how the table becomes readable.

| Operator | Does | Note |
|---|---|---|
| `project` | Keep *only* these columns, in this order | Also renames inline: `project Attacker = SourceIP` |
| `project-away` | Keep everything *except* these | Good for dropping `Type`, `TenantId`, `_ResourceId` noise |
| `project-keep` | Keep matching columns, original order | Accepts wildcards: `project-keep DeviceCustom*` |
| `project-rename` | Rename without reordering or dropping | `project-rename Attacker = SourceIP` |
| `project-reorder` | Reorder, keep everything | Cosmetic only |
| `extend` | Add a computed column, keep the rest | The workhorse |

`extend` then `project` is the normal pattern: compute first, then decide what to show.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(6h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| extend Command = DeviceCustomString3, SessionId = DeviceCustomString1
// severity arrives as a string; toint() so it can be compared or sorted numerically
| extend Sev = toint(LogSeverity)
| project TimeGenerated, SourceIP, SessionId, Command, Sev
| order by TimeGenerated desc
```

---

## 📊 Aggregation

`summarize` collapses many rows into few. Nobody wants 4,000 rows; they want
*how many*, *how many distinct*, or *how many per hour*.

| Function | Returns | Example |
|---|---|---|
| `count()` | Row count | `summarize count()` |
| `dcount(Col)` | Approximate distinct count — fast, ~1% error | `summarize dcount(SourceIP)` |
| `dcountif(Col, pred)` | Distinct count where a condition holds | `summarize dcountif(SourceIP, DeviceAction == "Denied")` |
| `countif(pred)` | Count of rows matching a condition | `summarize Fails = countif(DeviceEventClassID == "login.failed")` |
| `sum(Col)` / `avg(Col)` | Total / mean | `summarize sum(Quantity)` |
| `min(Col)` / `max(Col)` | Earliest / latest, smallest / largest | `summarize FirstSeen = min(TimeGenerated)` |
| `percentile(Col, 95)` | 95th percentile | `summarize percentile(TimeTaken, 95)` |
| `make_set(Col)` | Deduplicated array of values | `summarize Users = make_set(DestinationUserName)` |
| `make_list(Col)` | Array preserving order and duplicates | `summarize Commands = make_list(DeviceCustomString3)` |
| `arg_max(Col, *)` | The **whole row** where `Col` is highest | `summarize arg_max(TimeGenerated, *) by SourceIP` |
| `arg_min(Col, *)` | The whole row where `Col` is lowest | `summarize arg_min(TimeGenerated, *) by SourceIP` |

`by` turns one grand total into a breakdown. `bin()` inside `by` turns a breakdown into
a time series.

Brute-force shape per source IP — count, distinct usernames tried, and the window they
worked in, all in one pass:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts     = count(),
            UsersTried   = dcount(DestinationUserName),
            TopUsernames = make_set(DestinationUserName, 10),  // cap the array at 10
            FirstSeen    = min(TimeGenerated),
            LastSeen     = max(TimeGenerated)
        by SourceIP
| where Attempts > 20
| extend WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| order by Attempts desc
```

`dcount` is *approximate* by design — it uses a sketch instead of holding every value in
memory. For "roughly how many attackers", that is correct and cheap. When you need an
exact number on a small result set, use `summarize by Col | count` instead.

---

## 🔤 String matching — and which is faster

The one section worth reading twice. Every operator below returns a correct answer;
they differ enormously in how much data they force the engine to touch.

**Why there is a difference:** Log Analytics builds a **term index** over string columns.
It splits values into terms at non-alphanumeric characters, so `wget http://x.sh` indexes
as `wget`, `http`, `x`, `sh`. Operators that can consult that index skip entire blocks of
data without decompressing them. Operators that cannot must decompress and scan every
value. Case-insensitivity costs extra on top, because the engine has to fold case before
comparing.

| Operator | Matches | Case | Uses index? | Speed |
|---|---|---|---|---|
| `==` | Whole value, exactly | Sensitive | ✅ | 🟢 Fastest |
| `has_cs` | A whole term | Sensitive | ✅ | 🟢 Fastest |
| `has` | A whole term | Insensitive | ✅ | 🟢 Fast |
| `has_any` / `has_all` | Any / all of several terms | Insensitive | ✅ | 🟢 Fast |
| `hasprefix` / `hassuffix` | Term starts / ends with | Insensitive | ✅ | 🟢 Fast |
| `=~` | Whole value, exactly | Insensitive | ❌ | 🟡 Medium |
| `startswith_cs` | Value starts with substring | Sensitive | ❌ | 🟡 Medium |
| `startswith` | Value starts with substring | Insensitive | ❌ | 🟡 Medium |
| `contains_cs` | Substring anywhere | Sensitive | ❌ | 🔴 Slow |
| `contains` | Substring anywhere | Insensitive | ❌ | 🔴 Slowest |
| `matches regex` | Regex anywhere | Depends on pattern | ❌ | 🔴 Slowest |

**The rules that follow from that table:**

1. **`==` when you know the exact value.** Every `DeviceVendor`, `DeviceEventClassID`, and
   `DeviceAction` value in this lab is a known fixed string. There is never a reason to
   use `contains` on them.
2. **`has` when you are looking for a word inside free text.** That means
   `DeviceCustomString3` (commands) and `Activity` (signature names) — the only genuinely
   free-form fields here.
3. **`contains` only when you need a fragment inside a word,** and accept that it scans.
4. **`_cs` variants are free speed** when you already know the casing.

```kusto
// 🔴 Slow — decompresses and scans every command string in the range
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceCustomString3 contains "wget"

// 🟢 Fast — same rows, resolved against the term index
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has "wget"
```

💸 Over 7 days of continuous internet-facing honeypot traffic, that difference is the gap
between a query that returns instantly and one that grinds. Run the slow form a few dozen
times while iterating on a hunt and it is a measurable line on a $15/month budget.

> **The `has` trap.** `has` matches *whole terms only*. `DeviceCustomString3 has "get"`
> will **not** match `wget`, because `wget` is one term and `get` is not a term in it.
> When you genuinely need a fragment inside a word, `contains` is the correct tool and the
> scan is the price. Reach for it deliberately, not by habit.

> **The IP trap.** Do not use `has` for IP addresses. `192.168.1.10` indexes as four
> separate numeric terms, so term matching on it behaves unintuitively.
> `SourceIP == "203.0.113.45"` is both correct and faster.

Multiple terms in one pass, which is how the deployed rules do it:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any ("wget", "curl", "tftp")
| extend DownloadUrl = extract(@"(https?://[^\s]+)", 1, DeviceCustomString3)
| project TimeGenerated, SourceIP, SessionId = DeviceCustomString1,
          Command = DeviceCustomString3, DownloadUrl
```

---

## ⏱️ Time

`TimeGenerated` is a `datetime` in UTC in every table. The portal renders it in local time;
the data is UTC. When a timestamp in a screenshot disagrees with a query result by a fixed
number of hours, that is why.

| Function | Returns | Example |
|---|---|---|
| `ago(7d)` | Timestamp relative to now | `where TimeGenerated > ago(7d)` |
| `now()` | Current UTC time | `extend Age = now() - TimeGenerated` |
| `between (a .. b)` | Inclusive fixed window | `where TimeGenerated between (datetime(2026-08-01) .. datetime(2026-08-08))` |
| `bin(Col, 1h)` | Round down into fixed buckets | `summarize count() by bin(TimeGenerated, 1h)` |
| `startofday(Col)` | Midnight of that day | `summarize count() by startofday(TimeGenerated)` |
| `startofhour` / `startofweek` / `startofmonth` | Same idea, other granularities | `startofweek(TimeGenerated)` |
| `endofday(Col)` | Last instant of that day | `where TimeGenerated <= endofday(now())` |
| `datetime_diff('unit', later, earlier)` | Whole-number difference | `datetime_diff('minute', LastSeen, FirstSeen)` |
| `datetime_add('unit', n, Col)` | Shift a timestamp | `datetime_add('hour', -2, now())` |
| `format_datetime(Col, 'yyyy-MM-dd HH:mm')` | Pretty string for reports | Presentation only — do not filter on it |

Timespan literals: `1m`, `5m`, `1h`, `1d`, `7d`, `30d`. Subtracting two datetimes gives a
timespan directly (`LastSeen - FirstSeen`); `datetime_diff` gives a whole number in the unit
you name, which is what you want for a report column.

**Argument order matters and is easy to get backwards.** `datetime_diff` is
*later minus earlier*:

```kusto
// Correct — positive number of seconds from first network sighting to first shell connect
| extend SecondsFromScanToConnect = datetime_diff('second', FirstConnectSeen, FirstNetworkSeen)
```

Attack volume per hour over the last week, ready to chart:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
| render timechart
```

Use `ago()` while hunting. Switch to `between()` the moment you know the incident's real
window — "the last 7 days" silently means something different every time you run it, which
makes results impossible to compare across a shift.

---

## 🔗 Joins — the 5 kinds

Syntax is always `LeftTable | join kind=<kind> (RightTable) on <key>`. The smaller,
more-filtered table goes on the **left** — the left side is the one held in memory.

| Kind | Keeps | One-line summary |
|---|---|---|
| `innerunique` | Matched rows, left keys **deduplicated first** | **The default.** Silently drops duplicate left-side keys — rarely what you want |
| `inner` | Rows matched on both sides, all combinations | The honest inner join. Say it explicitly |
| `leftouter` | All left rows, right columns null where unmatched | "Enrich if you can" — add context without losing rows |
| `leftanti` | Left rows with **no** match on the right | "What is missing" — the most useful hunting join |
| `leftsemi` | Left rows that **do** have a match, left columns only | "Which of mine appear over there", no column bloat |

`rightouter`, `rightanti`, `rightsemi`, and `fullouter` exist and mirror the left forms.

> **Always write `kind=` explicitly.** Omitting it gives you `innerunique`, which quietly
> deduplicates the left side before matching. A brute-force count joined without `kind=`
> can come back dramatically too low with no error and no warning.

**Cross-source correlation — the highest-value query pattern in this workspace.** One IP
seen by both the network layer *and* the application layer within the same window is a
full attack progression: found the host, then tried to get in.

```kusto
let networkLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor in ("Suricata", "nftables")   // Doors 2 and 3
    | where isnotempty(SourceIP)
    | summarize NetworkEvents = count(), FirstNetworkSeen = min(TimeGenerated) by SourceIP;
let appLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "session.connect"
    | summarize ServiceConnections = count(), FirstConnectSeen = min(TimeGenerated) by SourceIP;
networkLayer
| join kind=inner appLayer on SourceIP
| extend SecondsFromScanToConnect = datetime_diff('second', FirstConnectSeen, FirstNetworkSeen)
| project SourceIP, NetworkEvents, ServiceConnections,
          FirstNetworkSeen, FirstConnectSeen, SecondsFromScanToConnect
| order by SecondsFromScanToConnect asc
```

**`leftanti` for absence** — IPs the IDS saw that never reached the shell. Either the
firewall stopped them, or they only scanned and moved on.

```kusto
let sawShell =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "sshd"
    | distinct SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| distinct SourceIP
| join kind=leftanti sawShell on SourceIP
```

**`union` is not a join.** It stacks rows from several tables rather than matching them
side by side. Use it when the same question spans tables:

```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0                       // 0 means success; anything else failed
| summarize Failures = count() by UserPrincipalName, IPAddress
| order by Failures desc
```

💸 `union` with a wildcard (`union *`) scans every table in the workspace. Never run it
here. Name your tables.

---

## 🧩 Parsing

| Tool | For | Example |
|---|---|---|
| `parse_json()` / `todynamic()` | Turn a JSON string into a navigable object | `parse_json(tostring(Status)).errorCode` |
| Dot / bracket access | Reach into a dynamic column | `DeviceDetail.operatingSystem`, `TargetResources[0].displayName` |
| `extract(regex, n, source)` | Pull capture group `n` out with regex | `extract(@"(https?://[^\s]+)", 1, DeviceCustomString3)` |
| `extract_all(regex, source)` | All matches as an array | `extract_all(@"(\d+\.\d+\.\d+\.\d+)", SyslogMessage)` |
| `split(source, delim)` | Split a string into an array | `split(DeviceEventClassID, ":")` |
| `parse` operator | Pattern-based extraction, no regex | `parse Activity with * "scan" *` |
| `mv-expand` | One array → one row per element | `mv-expand TargetResources` |
| `mv-apply` | Expand, run a subquery, re-collapse | Filter inside an array before re-aggregating |
| `bag_unpack` | Dynamic object → real columns | `evaluate bag_unpack(ParsedProps)` |

**Always `tostring()` before treating a dynamic field as a string.** Dynamic values compare
by JSON identity, not text, so a bare `==` against a dynamic field can fail while looking
correct.

Suricata's `DeviceEventClassID` is `gid:signature_id` — `split` separates them so you can
group by signature:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| extend Parts = split(DeviceEventClassID, ":")
| extend Gid = tostring(Parts[0]), SignatureId = tostring(Parts[1])
| summarize Hits = count(), Sources = dcount(SourceIP) by SignatureId, Signature = Activity
| order by Hits desc
```

`parse_json` against real dynamic columns — `SigninLogs` and `AuditLogs` are where dynamic
data actually lives in this workspace:

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| extend Country = tostring(LocationDetails.countryOrRegion),
         City    = tostring(LocationDetails.city),
         OS      = tostring(DeviceDetail.operatingSystem),
         Failure = tostring(Status.failureReason)
| summarize Failures = count() by UserPrincipalName, Country, City, Failure
| order by Failures desc
```

`mv-expand` turns an array column into rows. `AuditLogs.TargetResources` is an array —
one directory change can touch several objects:

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where Result == "success"
| mv-expand TargetResources                                  // one row per target now
| extend Target = tostring(TargetResources.displayName),
         TargetType = tostring(TargetResources.type)
| project TimeGenerated, OperationName, Target, TargetType,
          Actor = tostring(InitiatedBy.user.userPrincipalName)
| order by TimeGenerated desc
```

---

## 📚 Arrays and sets

| Function | Returns |
|---|---|
| `make_set(Col)` | Deduplicated array. Add a cap: `make_set(Col, 100)` |
| `make_list(Col)` | Array with order and duplicates preserved |
| `make_set_if(Col, pred)` | Set built only from rows matching a condition |
| `make_list_if(Col, pred)` | Same, as an ordered list |
| `array_length(arr)` | Element count |
| `array_index_of(arr, val)` | Position, or `-1` if absent |
| `set_union(a, b)` | Everything in either |
| `set_intersect(a, b)` | Only what is in both |
| `set_difference(a, b)` | In `a`, not in `b` |
| `strcat_array(arr, ", ")` | Flatten an array to a readable string for a report |
| `arg_max(Col, *)` | The whole row with the highest `Col` — the "latest state" tool |

**`make_list` vs `make_set` is a real decision, not a preference.** For a command timeline
you need `make_list` — the order *is* the evidence, and a repeated command run five times
is meaningful. `make_set` would destroy both facts.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| order by TimeGenerated asc                         // order BEFORE make_list
| summarize Commands   = make_list(DeviceCustomString3),
            CommandCount = count(),
            FirstCommand = min(TimeGenerated),
            LastCommand  = max(TimeGenerated)
        by SessionId = DeviceCustomString1, SourceIP
| where CommandCount > 1
| order by CommandCount desc
```

**`arg_max` is how you get the latest full row per entity**, not just the latest timestamp.
`summarize max(TimeGenerated) by SourceIP` gives you a timestamp and nothing else;
`arg_max(TimeGenerated, *)` gives you the entire row it came from.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd"
| summarize arg_max(TimeGenerated, *) by SourceIP     // whole latest row per attacker
| project SourceIP, TimeGenerated, DeviceEventClassID, Activity,
          DestinationUserName, DeviceAction
| order by TimeGenerated desc
```

The same trick answers "which sensors are alive" against `Heartbeat` — always the first
query to run when a table looks suspiciously quiet:

```kusto
Heartbeat
| where TimeGenerated > ago(24h)
| summarize arg_max(TimeGenerated, *) by Computer
| extend MinutesSinceLastBeat = datetime_diff('minute', now(), TimeGenerated)
| project Computer, OSType, TimeGenerated, MinutesSinceLastBeat
| order by MinutesSinceLastBeat desc
```

---

## 🎛️ Useful scalars

| Function | Does | Example |
|---|---|---|
| `iff(cond, a, b)` | Two-way branch (`iif` is the same function) | `iff(toint(LogSeverity) >= 7, "High", "Normal")` |
| `case(c1, v1, c2, v2, default)` | Multi-way branch, first match wins | See below |
| `coalesce(a, b, c)` | First non-null / non-empty value | `coalesce(DestinationUserName, "unknown")` |
| `isnotempty(x)` / `isempty(x)` | String has / lacks a value | `where isnotempty(DeviceCustomString3)` |
| `isnull(x)` / `isnotnull(x)` | Null checks for non-string types | `where isnotnull(DestinationPort)` |
| `toint` / `tolong` / `toreal` | Cast to a number | `toint(LogSeverity)` |
| `tostring` / `todatetime` | Cast to string / datetime | `tostring(TargetResources[0].type)` |
| `strcat(a, b, ...)` | Concatenate | `strcat(SourceIP, ":", tostring(SourcePort))` |
| `substring(s, start, len)` | Slice a string | `substring(SourceIP, 0, 7)` |
| `tolower` / `toupper` | Normalise case | `tolower(DestinationUserName)` |
| `trim(regex, s)` | Strip matching edges | `trim(@"\s", SyslogMessage)` |
| `replace_string(s, find, sub)` | Literal find-and-replace | `replace_string(Activity, "ET ", "")` |
| `bin(value, size)` | Round down to a bucket | `bin(toint(DestinationPort), 1000)` |

`case()` reads far better than nested `iff()` once you have more than two outcomes. Turning
the raw severity string into a triage label:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
// LogSeverity is a STRING - cast once, then compare numerically everywhere below
| extend Sev = toint(LogSeverity)
| extend Priority = case(Sev >= 8, "P1 - investigate now",
                         Sev >= 6, "P2 - investigate today",
                         Sev >= 3, "P3 - review in batch",
                                   "P4 - noise")
| summarize Events = count(), Sources = dcount(SourceIP) by Priority, DeviceVendor
| order by Priority asc
```

`coalesce` keeps a column readable when only some sensors populate it — remember that
`DestinationUserName` exists only on `sshd` login rows:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| extend Detail = coalesce(DestinationUserName, DeviceCustomString3, Activity)
| project TimeGenerated, DeviceVendor, SourceIP, Detail
```

---

## ⚠️ Gotchas

Each of these produces a *wrong answer* rather than an error message. That is what makes
them worth a table.

| Gotcha | What happens | Fix |
|---|---|---|
| **`LogSeverity` is a string** | `LogSeverity > 5` compares text — `"10"` sorts below `"3"` | `toint(LogSeverity) > 5` |
| **`==` is case-sensitive** | `DeviceVendor == "SSHD"` returns zero rows, no error | `=~` for case-insensitive, or fix the casing |
| **`has` beats `contains`** | `contains` decompresses and scans every value | `has` on free text, `==` on known values |
| **`has` misses fragments** | `has "get"` will not match `wget` — terms, not substrings | `contains` when you truly need a fragment |
| **`project` after `summarize` loses columns** | `summarize` drops everything that is not a `by` key or an aggregate; the later `project` fails to resolve the column | Put it in `by`, or capture it with `make_set()` / `any()` / `arg_max(TimeGenerated, *)` |
| **`let` must end with `;`** | The parser swallows the following lines into the `let` body; the error points at the wrong line | Semicolon after every `let`, none after the final query |
| **`join` defaults to `innerunique`** | Left-side duplicate keys silently deduplicated — counts come back too low | Always write `kind=inner` (or whichever you mean) explicitly |
| **`DeviceCustomString1` is overloaded** | Session id, Suricata priority, or interface depending on sensor | Pin `DeviceVendor` before touching it |
| **`DeviceEventCategory` is recent** | The Door labels were added in Aug 2026; older rows have it empty | Filter on `DeviceVendor` for anything spanning the rollout |
| **`Protocol` is empty on shell rows** | The `sshd` converter emits no protocol field | Do not filter shell events on `Protocol` |
| **`take` is not the top N** | `take 10` returns *any* 10 rows, and different ones each run | `top 10 by TimeGenerated desc` |
| **Retention is 30 days** | `ago(90d)` returns nothing — looks like "no activity" | Nothing older than 30 days exists. Export first if you need it |
| **Sysmon is down on the Arc laptop** | `SecurityEvent` has had no Sysmon depth since 2026-08-07 | Check `Heartbeat` before concluding "no activity" |
| **Dynamic fields need `tostring()`** | Comparing a dynamic value to a string can silently fail to match | `tostring(Status.failureReason) == "..."` |
| **`ResultType` is a string** | `ResultType == 0` in `SigninLogs` does not match | `ResultType == "0"`, or `!= 0` works via coercion — be consistent |
| **UTC everywhere** | Query results differ from portal timestamps by a fixed offset | The data is UTC; the portal renders local |

💸 **Two habits that cost money, not just time:** `search *` and `union *` both scan every
table in the workspace. Neither has any place in this lab. Name the table.

---

## 🧪 Sanity checks worth running weekly

Before trusting any hunt, confirm the sensors are actually feeding.

All three honeypot sensors reporting, with their last-seen time:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count(), LastSeen = max(TimeGenerated) by DeviceVendor
| extend MinutesSinceLastEvent = datetime_diff('minute', now(), LastSeen)
| order by MinutesSinceLastEvent desc
```

💸 What is actually costing you, biggest first. Run this before adding any new data source:

```kusto
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize BillableGB = sum(Quantity) / 1000 by DataType
| order by BillableGB desc
```

---

## 📌 The five-line version

If you remember nothing else from this page:

1. **Time filter first**, immediately after the table name.
2. **`==` for known values, `has` for free text.** `contains` only when you need a fragment.
3. **`toint(LogSeverity)`** before comparing severity, every single time.
4. **Pin `DeviceVendor`** before touching any `DeviceCustomString*` column.
5. **Write `kind=` on every join.** The default is not the one you want.

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
