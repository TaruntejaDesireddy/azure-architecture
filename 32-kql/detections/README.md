# Detections — from query to deployed rule

![Area](https://img.shields.io/badge/Area-detections-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)
![Retention](https://img.shields.io/badge/Retention-30%20days-0078D4?style=flat-square)

> A query answers a question you asked. A rule has to make a decision at 3am with nobody
> watching. Most of the work of turning one into the other is *removing* things.

Everything below runs against `la-lab-eus-01`. The honeypot is internet-facing and takes real
attacker traffic continuously, so `CommonSecurityLog` is the table with enough volume to make
threshold tuning a real exercise rather than a hypothetical one.

---

## 🔎 The gap

Here is a perfectly good hunting query. Run it in the Logs blade and it tells you something true.

```kusto
// Exploration: who is hammering the fake SSH service, and how hard?
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize Attempts = count() by SourceIP
| order by Attempts desc
```

As an analytics rule it is broken in three separate ways:

| Problem | Why it breaks the rule |
|---|---|
| `ago(24h)` | The rule already owns the time window. This line either lies or silently narrows it. |
| No entity columns survive | `SourceIP` is there, but nothing maps an account or a host — the incident opens with nothing to pivot on. |
| No threshold | One failed login is a row. This fires on literally every attacker packet, forever. |

Fix those three and you have a rule. The rest of this doc is those three, then how to test, then
the failure mode that hides all of it.

---

## ⏱️ Rule-ready #1 — take `ago()` out

A scheduled rule has two time settings, and they are the only two that matter:

| Setting | ARM name | What it means |
|---|---|---|
| Frequency | `queryFrequency` | How often the rule runs |
| Lookback | `queryPeriod` | How far back each run reads |

Sentinel injects the lookback for you. Your query text is executed *inside* a window that is
already `queryPeriod` wide. So an `ago()` in the query body does one of two unhelpful things:

- **`ago()` wider than `queryPeriod`** — no effect. `ago(24h)` in a rule with a 1-hour period
  still sees one hour. The line reads like it does something and does not. The next person to
  read the rule is misled.
- **`ago()` narrower than `queryPeriod`** — it wins, and quietly. A 24-hour period with
  `ago(1h)` inside reads one hour. You scanned and paid attention to 24 hours of intent for
  1 hour of coverage.

Neither is a crash. Both are wrong. Delete the line and set `queryPeriod` instead.

```kusto
// Rule-ready. No ago() — queryPeriod (set to 1h on the rule) supplies the window.
CommonSecurityLog
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize
    Attempts   = count(),
    UserCount  = dcount(DestinationUserName),
    UsersTried = make_set(DestinationUserName, 10),  // readable in the incident, see note below
    StartTime  = min(TimeGenerated),
    EndTime    = max(TimeGenerated)
  by SourceIP, Computer
| where Attempts >= 50
```

### The one exception

Absence detections need `ago()`, because the thing they measure is *how long ago* something last
happened. Those rules compare a timestamp to now, which is a different job from bounding a scan.
There is a worked example in the trap section below.

---

## 🧭 Rule-ready #2 — entities, or the incident is uninvestigable

An incident without entities is a paragraph of text. You cannot pivot from it, you cannot see
that three incidents share an IP, and the investigation graph is empty. This is the single most
common reason a technically-correct rule is useless in practice.

Entity mapping binds a column in your results to an entity type and one of its identifiers.
For the honeypot's CEF feed the natural mapping is:

| Entity type | Identifier | Column |
|---|---|---|
| IP | `Address` | `SourceIP` |
| Account | `Name` | `DestinationUserName` |
| Host | `HostName` | `Computer` |

Two rules of thumb that save real time:

**An identifier wants a scalar column.** `make_set(DestinationUserName, 10)` produces a dynamic
array. It is excellent in the alert description — the analyst sees the username spray at a glance
— but it is not a clean thing to hang an Account entity off. If you want Account as a *real*
entity, group by it so it stays a scalar:

```kusto
// One alert per (IP, username) pair — noisier, but every incident gets a full entity set.
CommonSecurityLog
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize Attempts = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated)
  by SourceIP, DestinationUserName, Computer
| where Attempts >= 25
```

That is a genuine trade-off, not a right answer. Grouping by `SourceIP` alone gives you one
incident per attacker; grouping by both gives you entity-complete incidents and more of them.
Pick based on who triages and how much time they have.

**Put the interesting strings in custom details.** The columns that make this honeypot worth
running are the ones the analyst would otherwise have to go re-query for:

| Column | For `sshd` | Worth surfacing as |
|---|---|---|
| `DeviceCustomString1` | session id | custom detail — ties events into one session |
| `DeviceCustomString2` | password tried | custom detail — the credential list is the story |
| `DeviceCustomString3` | command typed | custom detail — this is the payload |

Mapping those means the incident shows what was tried without a single pivot back to Logs.

---

## 📊 Rule-ready #3 — a threshold real traffic won't trip constantly

Do not pick a threshold by feel. Measure the traffic first, then pick a number above where it
normally sits, then check how many incidents that number would have produced.

**Step 1 — what does an hour of normal actually look like?**

```kusto
// Distribution of per-IP, per-hour failed logins across two weeks.
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize Attempts = count() by SourceIP, bin(TimeGenerated, 1h)
| summarize
    p50 = percentile(Attempts, 50),
    p95 = percentile(Attempts, 95),
    p99 = percentile(Attempts, 99),
    Max = max(Attempts)
```

**Step 2 — backtest the candidate number.** A threshold is only sane if you can look at the
incident count it would have generated and not flinch.

```kusto
// How many incidents would a threshold of 50 have opened, per day?
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize Attempts = count() by SourceIP, Window = bin(TimeGenerated, 1h)
| where Attempts >= 50                       // the candidate threshold
| summarize Incidents = count() by Day = bin(Window, 1d)
| order by Day asc
```

If that comes back at 40 a day, the threshold is wrong. Not "a bit noisy" — wrong. Nobody
triages 40 incidents a day, so the rule will be muted within a week and then it may as well not
exist. Raise the number until the daily count is something a human will actually look at.

> **Note on scan size.** Both queries above read 14 days of the busiest table in the workspace.
> They are the heaviest thing in this document. Run them when you are tuning, not on a loop.

### Threshold lives in the query, not in `triggerThreshold`

The rule also has a `triggerOperator` / `triggerThreshold` pair, which fires when the *number of
returned rows* passes a number. If your query already ends in `| where Attempts >= 50`, leave
`triggerThreshold` at `0` (fire when there is more than zero rows). Setting both is how you end
up with a rule that needs 50 attempts from each of 50 IPs before it says anything.

### While you are here: `LogSeverity` is a string

```kusto
// Suricata alerts at high severity.
CommonSecurityLog
| where DeviceVendor == "Suricata"
| where toint(LogSeverity) >= 8   // LogSeverity is a STRING — as text, "10" sorts below "8"
```

Comparing it without `toint()` does not error. It just quietly excludes your most severe events,
because string ordering puts `"10"` before `"8"`. The same applies to Suricata's priority in
`DeviceCustomString1`.

---

## ⚡ Scheduled vs NRT

| | Scheduled | NRT (near-real-time) |
|---|---|---|
| Timing | You choose frequency and lookback | Fixed: runs about every minute, over roughly the last minute |
| Latency | Bounded by your frequency | About a minute |
| Aggregation | Full KQL — `summarize`, `join`, `union` | Effectively single-event; a one-minute window gives counting nowhere to count |
| Table scope | Multiple tables | One table |
| Good for | "This IP tried 50 passwords" | "This one event should never happen" |

The distinction is not *speed*, it is *shape*. NRT trades away the ability to reason across time
in exchange for firing fast. That is the right trade only when a single event is condemning on
its own — when you do not need context to know it is bad.

On this honeypot, that describes file transfer onto the decoy exactly. Nobody has a legitimate
reason to push or pull a file on a box that only exists to be attacked.

```kusto
// NRT candidate: one of these is enough. No aggregation, no threshold, one table.
CommonSecurityLog
| where DeviceVendor == "sshd"
| where DeviceEventClassID in ("session.file_download", "session.file_upload")
| project
    TimeGenerated,
    SourceIP,
    DestinationUserName,
    Computer,
    Activity,
    SessionId = DeviceCustomString1,
    Command   = DeviceCustomString3
```

`nftables` `DENY-SENSITIVE` is the other natural NRT candidate here — the firewall has already
made the judgement call, so there is nothing left to aggregate.

> NRT's restrictions have moved around across Sentinel versions. Check the current limitation
> list in the Microsoft docs before you commit a rule to it, rather than trusting the shape of
> the table above to still be complete.

---

## 🧪 Testing before you enable

In order, because each step is cheap and catches things the next one would waste time on:

**1. Run it with an explicit `ago()` matching your intended `queryPeriod`.** This is the one
place that `ago()` belongs — a hand-run simulation of the window the rule will get. Confirm it
returns rows at all, and that the rows look like what you expect.

**2. Check the entity columns are actually populated.** A null identifier maps to nothing, and
the incident opens entity-less exactly as if you had never configured the mapping.

```kusto
// Would any alert land with an empty entity?
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize
    Total      = count(),
    NoSourceIP = countif(isempty(SourceIP)),
    NoUser     = countif(isempty(DestinationUserName)),
    NoComputer = countif(isempty(Computer))
```

Anything non-zero in those last three columns is a fraction of your future incidents arriving
uninvestigable.

**3. Backtest the volume** — the daily-incident query from the threshold section.

**4. Deploy it quiet first.** Create the rule at `Informational` severity, or with incident
creation off, and let it run for a day against live traffic. Then read what it produced and
raise the severity if it deserves it. A rule that goes straight to `High` on day one and is
wrong costs you the intern's trust in every rule after it.

**5. Set alert grouping deliberately.** A password spray produces a lot of alerts from one
source. `eventGroupingSettings` and the alert-grouping options decide whether that becomes one
incident with 400 alerts or 400 incidents. For anything volumetric, group by entity.

> **Backtests are capped at retention.** Workspace default retention here is 30 days. A backtest
> over 90 days does not warn you — it returns fewer results, or none, and looks like a clean
> baseline. Keep tuning windows inside 30 days.

---

## 🕳️ The trap — an empty table looks exactly like a quiet rule

This is the failure mode that undoes everything above, and it is invisible by construction.

A rule over a table with no data returns zero rows. A rule over a table full of data where
nothing bad happened also returns zero rows. **Both produce the same thing: silence.** Sentinel
does not distinguish them, the dashboard does not distinguish them, and the analyst reads both
as "we're fine."

There are two live examples of this in this workspace right now:

**The Sysmon feed from the Arc-connected laptop has been down since 2026-08-07.** Any detection
that depends on that host's telemetry has produced nothing since — not because the laptop is
clean, but because it stopped talking. The rules still show as healthy and enabled.

**`DeviceEventCategory` was only added to the CEF feed on 2026-08-22.** Every event before that
date has it empty. So a rule filtering on it looks perfectly reasonable and returns nothing for
any window that starts earlier — the field did not exist yet, which is indistinguishable from
"no traffic hit that door."

```kusto
// Sensor freshness. Run this by hand when a rule has been suspiciously quiet.
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize LastEvent = max(TimeGenerated), Events7d = count() by DeviceVendor
| extend SilentFor = now() - LastEvent
| order by SilentFor desc
```

Also worth knowing by hand — ingestion volume per table, which shows a feed dying as a cliff:

```kusto
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize GB = sum(Quantity) / 1024 by DataType, bin(TimeGenerated, 1d)  // Quantity is MB
| order by DataType asc, TimeGenerated asc
```

### You cannot detect a table's silence from inside that table

This is the part that catches people who already know about the trap. The obvious fix looks
like this, and it does not work:

```kusto
// BROKEN. Looks right, detects nothing.
CommonSecurityLog
| summarize LastEvent = max(TimeGenerated) by DeviceVendor
| where LastEvent < ago(1h)
```

If `sshd` died three days ago and `queryPeriod` is an hour, there are no `sshd` rows in the
window, so `summarize` emits no `sshd` row, so there is nothing for `where` to catch. The
sensor is more broken than the rule can see. Silence needs an anchor from outside the data.

```kusto
// Working shape: the expected roster lives in the query, so a row exists even at zero events.
let ExpectedSensors = datatable(DeviceVendor: string)
[
    "sshd", "telnetd", "Suricata", "nftables"
];
let Seen =
    CommonSecurityLog
    | summarize LastEvent = max(TimeGenerated) by DeviceVendor;
ExpectedSensors
| join kind=leftouter Seen on DeviceVendor   // leftouter keeps sensors that sent nothing
| where isnull(LastEvent) or LastEvent < ago(1h)
| project DeviceVendor, LastEvent, Computer = "db-finance-prod01"
```

Two things about deploying that one:

- It needs a **long `queryPeriod`** (14 days or so) for `LastEvent` to mean anything — a sensor
  dead for a week has no timestamp inside a one-hour window. This is the legitimate `ago()`
  exception from earlier: the `ago(1h)` here is the staleness test, not the scan bound.
- A 14-day period at hourly frequency re-reads two weeks of the busiest table 24 times a day.
  **Run it once or twice a day, not hourly.** Sensor death is not a minutes-matter event, and a
  summary rule is the better long-term home for this if you keep it.

`Heartbeat` is the other outside anchor, for agent-level rather than sensor-level silence:

```kusto
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
| extend SilentFor = now() - LastSeen
| where SilentFor > 1h
```

---

## 🚪 Worked example — chaining the doors

`DeviceEventCategory` records where in the traffic path a sensor sits. That makes a genuinely
useful detection possible: an IP that shows up at more than one door, and reached the shell.
The complexity here is doing something — it is the difference between "the firewall denied
something" and "somebody got through the firewall and the IDS and is now typing commands."

```kusto
CommonSecurityLog
| where isnotempty(DeviceEventCategory)
| extend Door = extract(@"^(Door \d)", 1, DeviceEventCategory)   // "Door 2" / "Door 3" / "Door 4"
| where isnotempty(Door)
| summarize
    Doors     = make_set(Door),
    DoorCount = dcount(Door),
    Events    = count(),
    StartTime = min(TimeGenerated),
    EndTime   = max(TimeGenerated)
  by SourceIP, Computer
| where DoorCount >= 2 and set_has_element(Doors, "Door 4")      // got past a control, reached the shell
```

> Only meaningful for data from **2026-08-22 onward** — `DeviceEventCategory` is empty before
> that. Backtesting this rule across the full 30 days will look like a quiet network. It is not;
> the field just did not exist. Set `queryPeriod` and your expectations accordingly.

---

## 💸 What actually costs money here

Worth being precise, because the intuition from other tools is wrong: **Log Analytics bills
ingestion and retention, not query execution.** A greedy scheduled rule does not add a line to
the invoice each time it runs.

What a greedy rule does cost:

| Cost | Where it lands |
|---|---|
| Rule query timeouts and throttling | The rule fails, and a failed rule is silent — see the trap above |
| Slow interactive queries | Your own hunting gets worse while heavy rules run |
| Pressure to retain more | Retention *is* billed, and this is where the $15/month goes |

So on this budget the lever is **what you ingest and how long you keep it**, not how tight the
`where` clause is. Filter at the DCR if a feed is noisy and you will never query it. `Syslog`
is kept here for investigation rather than detection for exactly this reason — the same host's
events are already structured in `CommonSecurityLog`, so build detections there and use
`Syslog` when you need the raw text during an investigation.

Efficiency in rule queries is still worth it — filter before you `summarize`, filter on
`DeviceVendor` and `DeviceEventClassID` early — but do it because it keeps the rule reliable,
not because you think each run is metered.

---

## 📚 38 worked examples

The lab has **38 analytics rules deployed** against this workspace. They are the answer key for
everything above — real thresholds tuned against real honeypot traffic, real entity mappings,
real decisions about scheduled vs NRT.

**→ [Detection library — `DETECTIONS/README.md`](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)**

Read them for the shape, not to copy. The useful exercise is to pick one, work out why its
threshold is the number it is, and then check your reasoning against what the rule actually does.

---

## ✅ Rule-ready checklist

| # | Check | ☐ |
|--:|---|:--:|
| 1 | No `ago()` in the body — unless this is an absence detection | ☐ |
| 2 | `queryFrequency` and `queryPeriod` set deliberately, and period ≥ frequency | ☐ |
| 3 | Entity mappings configured, on scalar columns | ☐ |
| 4 | Entity columns verified non-empty against real data | ☐ |
| 5 | Interesting strings surfaced as custom details, not left in the raw event | ☐ |
| 6 | Threshold measured from the baseline, not guessed | ☐ |
| 7 | Backtested for daily incident count — a human would actually triage that many | ☐ |
| 8 | `triggerThreshold` not double-counting a threshold already in the query | ☐ |
| 9 | `toint()` on `LogSeverity` and any other string-typed number | ☐ |
| 10 | Alert grouping set, so volumetric activity is one incident | ☐ |
| 11 | Ran quiet for a day before going to a real severity | ☐ |
| 12 | You know how you would tell this rule apart from a dead feed | ☐ |

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md) &nbsp;·&nbsp; [Hunting guide](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/08-hunting.md)
