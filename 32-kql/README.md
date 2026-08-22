# 32 — KQL

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Areas](https://img.shields.io/badge/Areas-22-0078D4?style=flat-square)
![Status](https://img.shields.io/badge/Status-not%20started-24292e?style=flat-square)

> This deserves its own huge section.

> **This is a map, not the material.** Write-ups live in
> [`azure-soc-lab`](https://github.com/TaruntejaDesireddy/azure-soc-lab) — the links below open the real thing. Keep your own
> work in the folders here.

## 🧠 What KQL actually is

KQL is a **read-only** language over an append-only store. There is no `UPDATE`, no `DELETE`,
no transaction — you point at one table, then push its rows through a pipeline of operators
with `|`. Every operator takes a table in and hands a table out, so a query reads strictly
left to right, top to bottom, and you can cut it off at any `|` to see what it looked like at
that point. That single habit — delete the last line, re-run, look — is most of learning KQL.

Almost every query you will ever write is the same four moves in the same order: **pick a
table → throw rows away (`where`) → throw columns away (`project`) → collapse what is left
into an answer (`summarize`)**. Operators, joins, parsing and time-series are all refinements
of those four. Start from a table you have data in and never write a query longer than you can
explain out loud.

Three facts about **`la-lab-eus-01`** that change how you write queries here:

| Fact | What it means for your queries |
|---|---|
| Retention is **30 days** | `ago(90d)` is not an error — it just quietly returns less. Anything older is gone. |
| The honeypot is **internet-facing and always on** | `CommonSecurityLog` always has fresh rows. You never need synthetic data to practise. |
| Budget is **$15/month** | On Analytics tables the bill is ingestion and retention, not the query itself — but a query that scans everything still costs you minutes and can time out, and any table moved to the Basic/Auxiliary tier *is* billed per GB scanned. Build the cheap habits now; see [performance](#9--performance--optimization--last-not-first). |

## 🔗 Learn this here

**KQL guides**

- [Logs](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/04-logs.md) &nbsp;·&nbsp; `HOWTO-GUIDES`
- [Hunting](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/08-hunting.md) &nbsp;·&nbsp; `HOWTO-GUIDES`
- [Summary rules](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/20-summary-rules.md) &nbsp;·&nbsp; `HOWTO-GUIDES`

**Saved queries**

- [Intern triage queue](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/KQL/intern-triage-queue.kql) &nbsp;·&nbsp; `KQL`
- [Storage blob logs](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/KQL/storage-blob-logs.kql) &nbsp;·&nbsp; `KQL`

**Paced KQL practice**

- [Part 02](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/SOC-L1-PATH/part-02.md) &nbsp;·&nbsp; `SOC-L1-PATH`

## 🎓 How to learn KQL here

The 22 folders below are **not** a list to pick from — they are a path, and the order matters.
Language mechanics first, then the tables, then the hunting, then the tuning. Working them out
of order is the usual way people end up writing detections they cannot debug.

Work in this order. Do not move to the next folder until you can write its query from memory,
against live data, without looking it up.

| # | Folder | What it buys you | Practise against |
|--:|---|---|---|
| 1 | `fundamentals/` | Read a query. Know what a table, a row and the `\|` actually are. | `CommonSecurityLog` |
| 2 | `operators/` | `where` · `project` · `extend` · `order by` · `take` · `distinct` | `CommonSecurityLog` |
| 3 | `summarize/` | Turn thousands of rows into one answer. `count()` · `dcount()` · `min/max` · `by` | `CommonSecurityLog` |
| 4 | `joins/` | Connect two questions into one. `join` kinds, and `let` to stay readable. | `CommonSecurityLog` (self-join on session id) |
| 5 | `parsing/` | Get structure out of text. `split()` · `parse` · `extract()` · `todynamic()` | Suricata rows, then `Syslog` |
| 6 | `time-series/` | See *when*, not just *how many*. `bin()` · `make-series` · `render` | `CommonSecurityLog` |
| 7 | The table-specific folders | Learn each log source's own vocabulary — one at a time. | see the table below |
| 8 | `threat-hunting/` → `detections/` | Ask a question nobody wrote a rule for; then turn the good ones into rules. | everything above |
| 9 | `performance/` + `optimization/` | Make it cheap and fast — **last**, once you know what "correct" looks like. | your own earlier queries |

`functions/` is not a stop on this path. Open it the moment you notice yourself pasting the
same `where`/`extend` block into a third query — that is what it is for, and it will make more
sense after `summarize/` and `parsing/` than before them.

---

### 1 · `fundamentals/`

**The question:** what does one row of this data even look like? You cannot filter a column you
have never seen. Start by looking, not by asking.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(15m)   // time filter first, always - it is the cheapest cut there is
| take 10                          // take = "any 10 rows", not "the newest 10" - just for shape
```

Then get the column list without paying for rows at all:

```kusto
CommonSecurityLog
| getschema
```

Read the result against the schema table further down. Note that `LogSeverity` comes back as a
**string** — that one detail will bite you in stage 2 if you skip it.

---

### 2 · `operators/`

**The question:** what is the internet trying right now? This is the everyday shape of the job —
cut rows down, cut columns down, look.

```kusto
// Failed SSH logins on the honeypot, with the username AND password the attacker tried
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| project TimeGenerated, SourceIP, DestinationUserName,
          PasswordTried = DeviceCustomString2   // sshd puts the attempted password in cs2
| order by TimeGenerated desc
| take 50
```

The stage-2 trap, and the reason `getschema` mattered:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where toint(LogSeverity) >= 7   // LogSeverity is TEXT in CEF - compare it as text and you get nonsense
```

---

### 3 · `summarize/`

**The question:** which source IPs are actually worth looking at? Fifty thousand rows is not an
answer; one ranked table is.

```kusto
// Rank today's brute-force sources by effort, and show how long each one stuck around
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts  = count(),
            Usernames = dcount(DestinationUserName),   // spray breadth, not just volume
            FirstSeen = min(TimeGenerated),
            LastSeen  = max(TimeGenerated)
  by SourceIP
| extend Duration = LastSeen - FirstSeen
| order by Attempts desc
| take 20
```

`count()` vs `dcount()` vs `countif()` is the whole stage. An IP with 4,000 attempts against one
username is a stuck script; 40 attempts across 30 usernames is someone enumerating.

---

### 4 · `joins/`

**The question:** who got in, and what did they do once they were in? Those are two different
event classes, and the only thing tying them together is the session id in `DeviceCustomString1`.

```kusto
// Successful sshd logins, matched to the commands typed inside that same session
let successful_logins =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "login.success"
    | project SessionId = DeviceCustomString1, LoginTime = TimeGenerated,
              SourceIP, DestinationUserName;
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| project SessionId = DeviceCustomString1, CmdTime = TimeGenerated,
          Command = DeviceCustomString3        // sshd puts the typed command in cs3
| join kind=inner successful_logins on SessionId   // inner: only sessions that truly authenticated
| project LoginTime, SourceIP, DestinationUserName, CmdTime, Command
| order by LoginTime asc, CmdTime asc
```

Two things to take from this one. `let` exists so a join stays readable — the alternative is a
single unreadable expression. And `kind=` is the actual decision: `inner` answers "both
happened", `leftouter` answers "this happened, and did that also happen?", `leftanti` answers
"this happened and that never did" — which is how a surprising number of detections are written.

---

### 5 · `parsing/`

**The question:** which Suricata signature is firing? The signature identity is buried inside a
`"gid:signature_id"` string, so you cannot group by it until you take it apart.

```kusto
// Split Suricata's "1:2024897" into its own columns, then rank today's signatures
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| extend Gid = tostring(split(DeviceEventClassID, ":")[0]),
         Sid = tostring(split(DeviceEventClassID, ":")[1])
| extend Priority = toint(DeviceCustomString1)   // Suricata's priority rides in cs1, as text
| summarize Hits = count(), Signature = take_any(Activity) by Sid, Priority
| order by Hits desc
```

Then do the same exercise against `Syslog`, which is raw unstructured text from the same host.
That is the harder, more honest version of this skill — and it is why `Syslog` is kept for
investigation and not used for detection.

---

### 6 · `time-series/`

**The question:** is this normal? A count with no time axis cannot tell you. Shape can.

```kusto
// Failed logins per hour for a week - look for the flat plateau of a script vs. human bursts
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts = count() by bin(TimeGenerated, 1h)
| render timechart
```

`bin()` silently omits empty hours, so an outage looks like a straight line rather than a gap.
When the *absence* of data is the point, use `make-series` instead:

```kusto
// default=0 fills the quiet hours, so a sensor going dark shows up as a floor, not a gap
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| make-series Attempts = count() default=0
  on TimeGenerated from ago(7d) to now() step 1h
| render timechart
```

Add `by SourceIP` to either one to get a line per attacker — readable up to about ten IPs, noise
after that. Pair it with `Heartbeat` when a drop looks suspicious: a sensor that stopped
reporting and a quiet internet produce the same-looking chart.

---

### 7 · The table-specific folders

Now, and only now, learn each log source's own vocabulary. One folder at a time — finish one
before opening the next, because the vocabularies do not transfer.

| Folder | What it means in `la-lab-eus-01` |
|---|---|
| `linux/` | `Syslog` — raw text from `db-finance-prod01`, plus the `sshd` rows in `CommonSecurityLog`. |
| `firewall/` | `CommonSecurityLog` where `DeviceVendor == "nftables"` — `ALLOW-SVC` / `DENY-SENSITIVE`, interface in cs1. |
| `network/` | `CommonSecurityLog` where `DeviceVendor == "Suricata"` — the inline IDS/IPS, signatures and priority. |
| `entra/` | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`. |
| `azure-activity/` | `AzureActivity` — the subscription control plane. Who changed what, in Azure itself. |
| `storage/` | `StorageBlobLogs` — blob read / write / delete. |
| `windows/` | `SecurityEvent` from the Arc-connected laptop. **Sysmon on it has been down since 2026-08-07** — do not build anything that depends on Sysmon telemetry until that is fixed. |
| `sentinel/` | `Heartbeat` and `Usage` — agent health and ingestion volume. This is also where you watch the $15 budget. |
| `key-vault/` · `defender/` | No data source feeding this workspace yet. Read them; do not expect queries to return rows. |

The honeypot's own sensors are laid out as doors along the traffic path, and `DeviceEventCategory`
tells you which door an event came through:

```kusto
// Where along the path is each sensor firing, and is it allowing or denying?
// DeviceEventCategory was only added on 2026-08-22 - rows older than that will come back blank.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count() by DeviceEventCategory, DeviceVendor, DeviceAction
| order by Events desc
```

And the budget query, which belongs in `sentinel/` and is worth running weekly:

```kusto
// Which table is eating the ingestion budget?
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize GB = sum(Quantity) / 1000 by DataType   // Quantity is in MB
| order by GB desc
```

---

### 8 · `threat-hunting/` → `detections/`

**The question:** what is happening that no rule is watching for? Hunting is where stages 1–7 stop
being exercises. A hunt is a hypothesis with a query attached; a detection is a hunt that proved
itself worth waking someone up for.

```kusto
// Hunt: an IP that failed, then succeeded, then actually did something.
// Failures alone are background noise. This is the shape of a break-in.
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| summarize Failed    = countif(DeviceEventClassID == "login.failed"),
            Succeeded = countif(DeviceEventClassID == "login.success"),
            Commands  = countif(DeviceEventClassID == "command.input"),
            Downloads = countif(DeviceEventClassID == "session.file_download"),
            Uploads   = countif(DeviceEventClassID == "session.file_upload")
  by SourceIP
| where Succeeded > 0 and (Commands > 0 or Downloads > 0 or Uploads > 0)  // got in AND acted
| order by Commands desc
```

Only then open `detections/`. **38 analytics rules are already deployed** in this workspace —
read them before writing a 39th, because the most common beginner detection is one that already
exists: [DETECTIONS library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).

A hunt becomes a rule only when it survives three questions: does it fire on the honeypot's
normal, continuous attacker traffic (if yes, it is noise)? can an intern tell from the alert
alone what to do next? and does it still work when the attacker changes one thing?

---

### 9 · `performance/` + `optimization/` — last, not first

**The question:** same answer, less work? Tune only what you already know is correct. Optimising a
wrong query is just making a wrong answer arrive faster.

The expensive way — no time filter, a string search across every column, and a sort applied
before the rows are cut down:

```kusto
CommonSecurityLog
| search "root"                 // searches EVERY column; with no table prefix it searches every table
| order by TimeGenerated desc   // sorting the whole table before reducing it
| take 20
```

The same answer, a fraction of the work:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)          // 1. time first
| where DestinationUserName == "root"     // 2. the exact column, exact match
| project TimeGenerated, SourceIP, DeviceEventClassID, DeviceCustomString2  // 3. only what you need
| take 20
```

The rules that do the work: filter on time first; filter on an indexed/exact column before a
`contains`; `project` away columns *before* a `join` or `summarize`, not after; and never `sort`
data you are about to throw away.

> **On cost, honestly.** On Analytics tables in `la-lab-eus-01` the money goes to ingestion and
> retention, not to the query — a bad query costs you minutes, not dollars, and can hit the
> portal's query timeout. But a table moved to the Basic or Auxiliary tier *is* billed by GB
> scanned, and a scheduled rule runs its query on a timer forever. Against a $15/month budget,
> a wasteful query that runs every 5 minutes is the one that eventually shows up on the bill.

## 📚 Cheat sheet and query library

Two different things, and it is worth keeping them apart. The cheat sheet is for **recall** —
you know the operator exists, you just want the syntax. The library is for **reuse** — a finished
query someone already debugged against real data.

| | Where | Reach for it when |
|---|---|---|
| 🗒️ **Cheat sheet** | [`cheat-sheets/`](cheat-sheets/) | You need the syntax, not the lesson. One page: operators, the aggregation functions, `bin` / `ago` / `todatetime`, the `join` kinds, and this workspace's `CommonSecurityLog` column map. Write it yourself as you finish each stage — a cheat sheet you copied is a cheat sheet you cannot use. |
| 📗 **Query library** | [azure-soc-lab `KQL/`](https://github.com/TaruntejaDesireddy/azure-soc-lab/tree/main/KQL) | You want a working query, not a starting point — e.g. [intern triage queue](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/KQL/intern-triage-queue.kql), [storage blob logs](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/KQL/storage-blob-logs.kql). |
| 🚨 **Detection library** | [azure-soc-lab `DETECTIONS/`](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md) | You are at stage 8 and about to write a rule. Read the 38 that already run before adding another. |

## 🧾 `CommonSecurityLog` in this lab

The richest table here, and the one every stage above practises on. This is how *this* lab
populates CEF — the same column means different things depending on `DeviceVendor`, which is
exactly why stage 7 exists.

| Column | What this lab puts in it |
|---|---|
| `DeviceVendor` | `sshd` / `telnetd` (the fake shell), `Suricata` (inline IDS/IPS), `nftables` (host firewall) |
| `DeviceEventClassID` | sshd: `session.connect` · `login.failed` · `login.success` · `command.input` · `session.file_download` · `session.file_upload` — Suricata: `gid:signature_id`, e.g. `1:2024897` — nftables: `ALLOW-SVC` · `DENY-SENSITIVE` |
| `DeviceEventCategory` | The sensor's position in the traffic path (added 2026-08-22): `Door 2 - Host Firewall`, `Door 3 - Network IDS/IPS - <cat>`, `Door 4 - Application Shell (SSH)` |
| `DeviceAction` | `Allowed` · `Denied` |
| `SourceIP` · `DestinationIP` · `SourcePort` · `DestinationPort` · `Protocol` | The connection itself |
| `DestinationUserName` | The username that was tried |
| `DeviceCustomString1` | sshd: session id · Suricata: priority · nftables: interface |
| `DeviceCustomString2` | sshd: the password that was tried |
| `DeviceCustomString3` | sshd: the command that was typed |
| `Activity` | Human-readable event name, or the Suricata signature name |
| `LogSeverity` | CEF severity **as a string** — wrap it in `toint()` before comparing |
| `Computer` | `db-finance-prod01` |

## 🪜 Progression

Work each area through these stages rather than stopping at "deployed":

| # | Stage | Done |
|--:|---|:--:|
| 1 | Understand | ☐ |
| 2 | Deploy | ☐ |
| 3 | Secure | ☐ |
| 4 | Misconfigure (isolated lab) | ☐ |
| 5 | Detect | ☐ |
| 6 | Investigate | ☐ |
| 7 | Remediate | ☐ |
| 8 | Automate | ☐ |
| 9 | Architect | ☐ |

> Stage 4 is **isolated-lab only**. Never misconfigure something reachable from the internet
> or shared with anything real.

## 🗂️ Areas (22)

| Area | |
|---|---|
| `fundamentals/` | ☐ |
| `operators/` | ☐ |
| `functions/` | ☐ |
| `joins/` | ☐ |
| `summarize/` | ☐ |
| `parsing/` | ☐ |
| `time-series/` | ☐ |
| `performance/` | ☐ |
| `optimization/` | ☐ |
| `entra/` | ☐ |
| `azure-activity/` | ☐ |
| `firewall/` | ☐ |
| `network/` | ☐ |
| `storage/` | ☐ |
| `key-vault/` | ☐ |
| `defender/` | ☐ |
| `sentinel/` | ☐ |
| `windows/` | ☐ |
| `linux/` | ☐ |
| `threat-hunting/` | ☐ |
| `detections/` | ☐ |
| `cheat-sheets/` | ☐ |

## 📎 Additional topics (10)

Carried over from the earlier 23-module roadmap — concepts it tracked that this
module has no dedicated folder for.

- [ ] This should become a major personal KQL library.
- [ ] SigninLogs
- [ ] ResourceChanges
- [ ] Parse
- [ ] Extend
- [ ] Project
- [ ] Where
- [ ] Dynamic data
- [ ] Variables
- [ ] Entity extraction

---

[← Roadmap](../README.md) &nbsp;·&nbsp; [Certification mapping](../certification-mapping/)
