# Performance — making KQL fast and cheap

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Area](https://img.shields.io/badge/Area-performance-0078D4?style=flat-square)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)

> Every query on this page is written against `la-lab-eus-01` — the real workspace, the real
> honeypot feed. Nothing here is a made-up sample table.

The honeypot `db-finance-prod01` is internet-facing and takes real attacker traffic continuously,
so `CommonSecurityLog` is never empty and never small. There are **38 analytics rules** deployed
against it ([detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)),
each one re-running its query on a schedule forever. Workspace retention is **30 days**. The whole
lab runs on a **$15/month** budget.

That combination is why this area exists. A sloppy ad-hoc query wastes a few minutes. A sloppy
query inside a scheduled rule wastes them every five minutes, permanently.

---

## 🧾 Be honest about what a query actually costs

Most "KQL cost" advice quietly conflates two different meters. Separate them before optimising
anything, or you will tune the wrong thing.

| What you do | Does it add to the bill? |
|---|---|
| Run an ad-hoc query in **Logs** against an Analytics-tier table | **No** — you paid for that data at ingestion |
| Ingest another GB | **Yes**, and again for retention beyond the included period |
| Keep a chatty scheduled rule running every 5 minutes | Not per-run, but it is permanent load and it drives alert volume |
| Query a **Basic** or **Auxiliary** tier table | **Yes** — those are billed per GB scanned by the search job |
| Export results out of the workspace | **Yes** |

So on an Analytics-tier workspace, the payoff from tuning an interactive query is **time, query
quota, and your own patience** — not dollars. Azure Monitor will kill a query at the 10-minute
mark and truncates very large result sets, and a workspace has finite concurrent query capacity
that 38 scheduled rules are already using.

The dollars live one step upstream, at **ingestion**. But the instinct is identical: filter early,
keep less, drop what you will not read. Learn it here on queries, then apply the same thinking to
DCR transformations, where it does move the bill.

**Where it costs real money on this page:** nothing below touches Basic or Auxiliary tables, so
none of these queries bill you. The ones flagged 🐢 will simply take a long time and may not
finish.

---

## ⏱️ Rule 1 — time first, then the most selective filter

Log Analytics partitions data by ingestion time. A `where TimeGenerated` filter is the only filter
that lets the engine skip whole chunks of storage without looking inside them. Every other filter
is applied to rows it has already read.

So the time filter is not just *a* filter — it decides how much data the rest of the query ever
sees. Put it first, always, and make it as tight as the question allows.

After time, order the remaining `where` clauses **most-selective first**. Each stage hands fewer
rows to the next one.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)                    // 1. narrows the storage scan itself
| where DeviceVendor == "sshd"                      // 2. one of three vendors — cuts hard
| where DeviceEventClassID == "login.success"       // 3. rarest sshd event class
| where toint(LogSeverity) >= 7                     // 4. last: needs a conversion, so no index
| project TimeGenerated, SourceIP, DestinationUserName, DeviceCustomString1
```

`LogSeverity` arrives as a **string** in this lab's CEF feed, so it needs `toint()` before any
numeric comparison. That conversion runs per row and cannot use an index, which is exactly why it
belongs at the bottom of the filter stack — by the time it runs, three cheap filters have already
thrown most of the rows away.

### Retention is a filter too

Nothing older than 30 days exists here. `ago(90d)` does not fail, it just returns the same rows as
`ago(30d)` after making the engine confirm there is nothing else. Ask for what can exist.

> ⚠️ **`DeviceEventCategory` was only added on 2026-08-22.** It is the most readable column in the
> schema — `"Door 2 - Host Firewall"`, `"Door 3 - Network IDS/IPS - <cat>"`,
> `"Door 4 - Application Shell (SSH)"` — and it is tempting to filter on. But over any window that
> reaches back before that date it silently drops every older row. Until the field has aged past
> the 30-day retention window, filter on `DeviceVendor` for anything historical and treat
> `DeviceEventCategory` as a display column.

---

## 🔤 Rule 2 — `==`, then `has`, then `contains`, then regex

String matching is where most wasted time goes, and the four options are not close to each other.
The table is ordered cheapest to most expensive.

| Operator | How it matches | Cost | Use it when |
|---|---|---|---|
| `==`, `in` | Whole value, exact, case-sensitive | Cheapest | You know the exact value |
| `has`, `has_any` | Whole **terms**, using the term index | Cheap | Looking for a word inside free text |
| `startswith`, `hasprefix` | Prefix, partial index help | Moderate | Structured prefixes |
| `contains` | Any substring, no index | Expensive | Genuinely need a fragment inside a word |
| `matches regex` | Full regex engine, per row | Most expensive | Nothing simpler can express it |

Two things that surprise people:

**`has` matches terms, not substrings.** Kusto breaks text on non-alphanumeric characters, so
`DeviceCustomString3 has "credentials"` matches the command `cat /root/.aws/credentials` — the
slashes and dots are delimiters. But `has "cred"` will **not** match it, because `cred` is not a
whole term. If you need a fragment inside a word, `contains` is the honest answer; just know what
you are paying.

**Terms shorter than four characters are not in the index.** `has "ls"` falls back to scanning, so
it buys you nothing over `contains`. Anchor on a longer term when you can.

Same question, three ways — find attacker commands that pull a payload down:

```kusto
// ✅ Term-indexed. "wget", "curl" and "tftp" are all 4 characters, so all three hit the index.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any ("wget", "curl", "tftp")
| project TimeGenerated, SourceIP, Command = DeviceCustomString3
```

```kusto
// 🐢 Same answer, substring scan on every surviving row. No index.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 contains "wget"
       or DeviceCustomString3 contains "curl"
       or DeviceCustomString3 contains "tftp"
| project TimeGenerated, SourceIP, Command = DeviceCustomString3
```

```kusto
// 🐢🐢 Regex engine, per row, for a job three literals already do.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 matches regex @"(?i)(wget|curl|tftp)"
| project TimeGenerated, SourceIP, Command = DeviceCustomString3
```

Regex earns its place when you need **structure**, not membership — pulling the URL out of a
command once the cheap filter has already cut the row count:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any ("wget", "curl", "tftp")   // cheap filter first
| extend DownloadUrl = extract(@"(https?://[^\s]+)", 1, DeviceCustomString3)  // regex on survivors only
| where isnotempty(DownloadUrl)
| project TimeGenerated, SourceIP, DownloadUrl, Command = DeviceCustomString3
```

That ordering is the whole trick: **filter with the index, extract with the regex.**

### The cheapest filter is often a different filter

`DeviceEventCategory startswith "Door 3"` and `DeviceVendor == "Suricata"` select the same sensor,
because Door 3 *is* Suricata. One is a prefix scan on a long string, the other is an exact match on
a short one. Before optimising a filter, check whether an equivalent cheaper column exists.

---

## 🚫 Rule 3 — never `search *`

`search "203.0.113.10"` with no table scope asks the engine to look in **every table in the
workspace, in every column**. In this workspace that means `CommonSecurityLog`, `Syslog`, five
Entra sign-in tables, `AuditLogs`, `AzureActivity`, `SecurityEvent`, `StorageBlobLogs`,
`AppServiceHTTPLogs`, `Heartbeat` and `Usage` — most of which cannot possibly contain the answer.

```kusto
// 🐢🐢 Don't. Reads everything, in every column, to answer a one-table question.
search "203.0.113.10"
| where TimeGenerated > ago(24h)
```

If you genuinely do not know which column holds the value, scope the search to the table first —
still not cheap, but bounded:

```kusto
// Acceptable while exploring: scoped to one table, tight time window.
search in (CommonSecurityLog) "203.0.113.10"
| where TimeGenerated > ago(1h)
| take 20
```

And once you know the column — which after one look you always do — use `where`:

```kusto
// ✅ The real query.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SourceIP == "203.0.113.10"
| project TimeGenerated, DeviceVendor, DeviceEventClassID, DestinationPort, DeviceAction, Activity
| order by TimeGenerated desc
```

`search` is a discovery tool for your first five minutes in an unfamiliar table. It should never
survive into a saved query, a workbook, or an analytics rule.

---

## ✂️ Rule 4 — project early, drop what you will not read

`CommonSecurityLog` is a wide table — the CEF schema carries dozens of columns, and this lab
populates maybe a dozen of them meaningfully. Every column you carry forward is memory moved
through every subsequent stage.

For a plain `where` + `take`, projecting late costs little. It matters enormously **before a
`sort`, a `join`, or a `summarize`**, because those stages have to hold rows in memory.

```kusto
// ✅ Down to five columns before the sort has to buffer anything.
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| project TimeGenerated, SourceIP, DestinationUserName, Password = DeviceCustomString2   // early
| summarize Attempts = count(), Passwords = dcount(Password) by SourceIP, DestinationUserName
| order by Attempts desc
| take 25
```

Use `project-away` when you want almost everything, and `project` when you want a named few. Naming
columns as you project (`Password = DeviceCustomString2`) is worth the keystrokes — nobody reading
`DeviceCustomString2` in a workbook six weeks later will remember it holds the password tried.

### `take` is not a discount on a `sort`

`| take 25` on its own is cheap — the engine stops early. `| sort by X | take 25` is **not**: every
row has to be ordered before the first 25 exist. When you want the largest N, say so directly with
`top`, which is the operator built for exactly that:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts = count() by SourceIP
| top 25 by Attempts desc      // clearer intent than sort + take, and the engine knows it
```

---

## 🔗 Rule 5 — summarize before you join

A join is the most expensive thing in a normal SOC query, and its cost scales with how many rows
reach it. So the fix is not to avoid joins — it is to **shrink both sides to one row per key
first**.

The lab's own *Network Scan Followed By Interactive Login Attempt* rule is built this way, and it
is the pattern to copy: each side collapses to one row per `SourceIP` before the join happens.

```kusto
// ✅ Both sides are aggregated first, so the join sees hundreds of rows, not millions.
let window = 7d;
let networkLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(window)
    | where DeviceVendor in ("Suricata", "nftables")
    | where isnotempty(SourceIP)
    | summarize NetworkEvents = count(), FirstNetworkSeen = min(TimeGenerated) by SourceIP;
let appLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(window)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "session.connect"
    | summarize ServiceConnections = count(), FirstConnectSeen = min(TimeGenerated) by SourceIP;
networkLayer
| join kind=inner appLayer on SourceIP
| extend SecondsFromScanToConnect = datetime_diff('second', FirstConnectSeen, FirstNetworkSeen)
| project SourceIP, NetworkEvents, ServiceConnections, FirstNetworkSeen, SecondsFromScanToConnect
| order by SecondsFromScanToConnect asc
```

Three more things worth knowing about joins:

**Always write the `kind=` explicitly.** A bare `join` defaults to `kind=innerunique`, which
silently deduplicates the left side's keys. That is occasionally what you want and usually not, and
a rule that quietly drops rows is worse than a slow one.

**Put the smaller side on the left.** Kusto's documented guidance; it affects how the join is
executed.

**Sometimes you do not need a join at all.** If you only want to *filter* by membership rather than
combine columns, build a set and use `has_any` / `in` — far cheaper than a join:

```kusto
// Which usernames were tried by IPs that the firewall had already denied?
let deniedIPs =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "nftables" and DeviceAction == "Denied"
    | distinct SourceIP;          // a set, not a table to join against
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| where SourceIP in (deniedIPs)   // membership test, no join
| summarize Attempts = count() by SourceIP, DestinationUserName
| top 20 by Attempts desc
```

If a `let` result is used **more than once** in the same query, wrap it in `materialize()` so it is
computed once instead of re-evaluated per reference.

---

## 🌐 Rule 6 — it is the `*` in `union withsource = X *`, not the `withsource`

`withsource = SourceTable` is nearly free. It just stamps each row with the table it came from,
which is genuinely useful for "where else did this IP show up." The expensive part is the `*`.

```kusto
// 🐢🐢 Reads every table in the workspace, then filters. Also `where * has` scans every column.
union withsource = SourceTable *
| where TimeGenerated > ago(1d)
| where * has "203.0.113.10"
```

You almost always know which two or three tables could hold an IP address. Name them, filter each
one *inside* its own branch so the filter runs before the union, and keep `withsource`:

```kusto
// ✅ Same answer, three named tables, each filtered before anything is combined.
let ip = "203.0.113.10";      // swap in the address you are chasing
let window = 1d;
union withsource = SourceTable
    ( CommonSecurityLog
      | where TimeGenerated > ago(window)
      | where SourceIP == ip
      | project TimeGenerated, Detail = strcat(DeviceVendor, " / ", Activity) ),
    ( SigninLogs
      | where TimeGenerated > ago(window)
      | where IPAddress == ip
      | project TimeGenerated, Detail = strcat(UserPrincipalName, " / ", tostring(ResultType)) ),
    ( AppServiceHTTPLogs
      | where TimeGenerated > ago(window)
      | where CIp == ip
      | project TimeGenerated, Detail = strcat(CsMethod, " ", CsUriStem) )
| order by TimeGenerated asc
```

The filter placement is the point. Filtering **inside** each branch means each table is narrowed
before the union assembles anything; a single `| where` after the union means every row from every
branch is materialised first.

---

## 🔬 Rule 7 — scout before you commit

Before running anything broad, spend ten seconds finding out how big the thing you are about to
read actually is. Three cheap probes, in increasing order of what they tell you.

### `Usage` — how much data is in each table

`Usage` is the workspace's own ingestion ledger. It will not tell you what one specific query
scans, but it tells you the size and shape of the table, which is the proxy you need.

```kusto
// Which tables are actually large here? Quantity is in MB.
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize GB = round(sum(Quantity) / 1024, 3) by DataType
| order by GB desc
```

Then ask whether the growth is steady or spiky, which is how you spot the table that will make a
30-day query painful:

```kusto
Usage
| where TimeGenerated > ago(14d)
| where DataType == "CommonSecurityLog"
| summarize MB = round(sum(Quantity), 1) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

### `count` — how many rows survive your filter

Run the filter with nothing after it. This is the single most useful habit on this page: it costs
one line and tells you whether the projection, join and sort you were about to write are going to
operate on 400 rows or 4 million.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| count                            // decide what to write next based on this number
```

### `take` — what the rows actually look like

`take` is non-deterministic and that is fine; you are checking shape, not answering a question.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Suricata"
| take 5                           // are the fields populated the way I assumed?
```

### Scout the source before you hunt in it

Sysmon on the Arc-connected laptop has been **down since 2026-08-07**. A 30-day hunt through
`SecurityEvent` for process-creation detail will run fine, take a while, and return an incomplete
picture — because the data stopped, not because the attacker was quiet. Check liveness first:

```kusto
// Is this source still reporting, and when did it last say anything?
Heartbeat
| where TimeGenerated > ago(7d)
| summarize LastSeen = max(TimeGenerated) by Computer, Category
| order by LastSeen asc
```

A minute spent here saves a wrong conclusion, which is more expensive than any query.

---

## 🧪 Before / after — one real question, two queries

**The question:** in the last 7 days, which source IPs got a *successful* login on the honeypot and
then tried to pull a payload down — and how fast did they move?

### Before

This is genuinely the shape of a first attempt. Do not run it.

```kusto
// 🐢🐢 Seven mistakes, numbered below.
search "wget"                                     // ① scans every table in the workspace
| where TimeGenerated > ago(7d)                   // ② time filter arrives after the scan
| where DeviceCustomString3 matches regex @"(?i)(wget|curl|tftp)"  // ③ regex where literals would do
| join kind=inner (
    CommonSecurityLog                             // ④ right side is 7 days of everything, unfiltered
  ) on SourceIP
| where DeviceEventClassID1 == "login.success"    // ⑤ filtering after the join instead of before
| project TimeGenerated, SourceIP, DestinationUserName1, DeviceCustomString3   // ⑥ columns dropped last
| order by TimeGenerated desc                     // ⑦ sorts every row that survived
```

Those `1` suffixes in ⑤ and ⑥ are Kusto renaming the right side's colliding column names. Needing
them is itself the warning: you joined two things that were both far too wide.

### After

```kusto
// ✅ Same question. Each read is narrow, and the join sees one row per IP.
let window = 7d;
// Side 1 — IPs that actually authenticated. Collapse to one row per IP before joining.
let succeeded =
    CommonSecurityLog
    | where TimeGenerated > ago(window)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "login.success"
    | summarize LoginCount  = count(),
                Usernames   = make_set(DestinationUserName, 10),
                FirstLogin  = min(TimeGenerated)
              by SourceIP;
// Side 2 — download commands. has_any is term-indexed; all three terms are 4 characters.
let downloads =
    CommonSecurityLog
    | where TimeGenerated > ago(window)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
    | where DeviceCustomString3 has_any ("wget", "curl", "tftp")
    | summarize DownloadCmds  = count(),
                Commands      = make_set(DeviceCustomString3, 5),
                FirstDownload = min(TimeGenerated)
              by SourceIP;
succeeded
| join kind=inner downloads on SourceIP           // both sides are already one row per IP
| extend SecondsToPayload = datetime_diff('second', FirstDownload, FirstLogin)
| project SourceIP, Usernames, LoginCount, DownloadCmds, SecondsToPayload, Commands
| order by SecondsToPayload asc                   // fastest movers first — those are the automated ones
```

### What changed

No invented timings here — these are structural differences you can read straight off the two
queries.

| | Before | After |
|---|---|---|
| Tables read | Every table in the workspace | `CommonSecurityLog` only |
| Time filter | After the scan | First line of both branches |
| String match | `matches regex` | `has_any`, term-indexed |
| Rows entering the join | Every 7-day `CommonSecurityLog` row on the right | One row per source IP, both sides |
| Where filtering happens | After the join | Before each `summarize` |
| Columns carried | All of them until the last step | Five, named, after aggregation |
| Sort input | Everything that survived | One row per matching IP |

The after-query still reads `CommonSecurityLog` twice over 7 days, and that is fine — the point was
never to read the table less often, it was to make each read narrow and to make the join cheap. Two
tight scans beat one sprawling one.

**Read the receipts.** The Logs results pane reports how many records came back and how long the
query took. Run both shapes once each on a **1-hour** window rather than 7 days, compare those two
numbers, and the argument stops being theoretical.

---

## 📋 The checklist

Run down this list before saving any query, and especially before pasting one into an analytics
rule — that is the one that will run forever.

| ✔ | Check |
|:--:|---|
| ☐ | `TimeGenerated` filter is the **first** `where`, and as tight as the question allows |
| ☐ | Remaining filters ordered most-selective first; conversions like `toint(LogSeverity)` last |
| ☐ | No bare `search` and no `union *` anywhere in the query |
| ☐ | `has` / `has_any` / `==` used instead of `contains` or regex, unless a fragment is genuinely needed |
| ☐ | Regex only runs on rows a cheap filter already selected |
| ☐ | `project` happens **before** any `sort`, `join`, or `summarize` |
| ☐ | Both sides of every join are summarised or filtered down first |
| ☐ | Every `join` states its `kind=` explicitly |
| ☐ | `top N by X` used instead of `sort` + `take` |
| ☐ | `let` results referenced more than once are wrapped in `materialize()` |
| ☐ | Lookback is within the 30-day retention window |
| ☐ | Any filter on `DeviceEventCategory` accounts for the field only existing since 2026-08-22 |
| ☐ | You ran `| count` on the filter before writing everything after it |
| ☐ | You checked `Heartbeat` if the query depends on a source that could be dead |

---

## 🪜 Progression for this area

| # | Stage | What it means here | Done |
|--:|---|---|:--:|
| 1 | Understand | Explain why time-first beats every other filter | ☐ |
| 2 | Deploy | Rewrite one saved query in `KQL/` using the checklist | ☐ |
| 3 | Secure | — | ☐ |
| 4 | Misconfigure | Run the "before" query on a 1-hour window and watch it | ☐ |
| 5 | Detect | Audit the 38 deployed rules for `contains` and unfiltered joins | ☐ |
| 6 | Investigate | Scout with `Usage` + `count` before your next 30-day hunt | ☐ |
| 7 | Remediate | Fix the worst rule query found in stage 5 | ☐ |
| 8 | Automate | Apply the same filter-early thinking to a DCR transformation | ☐ |
| 9 | Architect | Decide which tables belong on a cheaper tier | ☐ |

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [`../optimization/`](../optimization/) &nbsp;·&nbsp; [`../summarize/`](../summarize/) &nbsp;·&nbsp; [`../joins/`](../joins/)
