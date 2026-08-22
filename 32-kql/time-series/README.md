# 32 — KQL · Time series

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Area](https://img.shields.io/badge/Area-time--series-0078D4?style=flat-square)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)

> Every query in this file is written against the real tables in `la-lab-eus-01`. Nothing here uses
> a table or column the lab doesn't populate. Where a query is expensive or has a caveat, it says so
> in the text — not in a footnote.

Security data is time data. An IP address is not interesting; an IP address that appeared for the
first time forty minutes ago is. A thousand failed logins is not interesting; a thousand failed
logins in an hour that normally sees nine is.

This area covers the operators that turn "what happened" into "what changed".

---

## Contents

1. [Why `TimeGenerated` goes first](#-1--why-timegenerated-goes-first)
2. [`ago()`, `between()`, `startofday()`](#-2--ago-between-startofday)
3. [`bin()` — bucketing](#-3--bin--bucketing)
4. [`make-series` and `series_decompose_anomalies`](#-4--make-series-and-series_decompose_anomalies)
5. [Durations with `datetime_diff`](#-5--durations-with-datetime_diff)
6. [First seen — new, or always been here?](#-6--first-seen--new-or-always-been-here)
7. [What actually costs money](#-7--what-actually-costs-money)
8. [Gotchas](#-8--gotchas)

---

## ⏱️ 1 — Why `TimeGenerated` goes first

Log Analytics stores every table partitioned by time. When you constrain `TimeGenerated`, the engine
skips whole partitions before it reads a single row of data. Every other filter you write —
`SourceIP`, `DeviceVendor`, a `contains` on a command string — can only be evaluated on rows that
have already been read off disk.

That is the whole lever. **A time filter reduces what gets read. Every other filter reduces what
survives being read.**

So this:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)          // partition pruning happens here
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
```

and not this:

```kusto
CommonSecurityLog
| where DeviceEventClassID == "login.failed"   // evaluated against everything in range
| where TimeGenerated > ago(1h)
```

The optimiser will often rescue the second form. Write the first anyway — it is a habit that stops
mattering only until the day you write something the optimiser can't reorder, and by then the query
is in an analytics rule running every five minutes.

### The time picker and the query are ANDed

The Logs blade has a time-range picker. If your query also filters `TimeGenerated`, the effective
window is the **intersection** of the two — the narrower one wins. A query saying `ago(7d)` run with
the picker on **Last hour** returns one hour of data, which is a genuinely confusing way to lose six
days of results.

The blade notices an in-query filter and switches the picker to **Set in query**. Trust the query,
not your memory of where you left the dropdown.

### The one place you must not write `ago()`

Analytics rules scope their own time window via `queryPeriod`. An `ago()` left inside a rule query
produces an effective window that is the intersection of the two, which is almost never what anyone
meant. The 38 rules in the
[detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
follow that rule; hunting queries in this file deliberately do not, because a human runs them.

### `TimeGenerated` is not exactly when the attacker acted

For the honeypot feed, `TimeGenerated` is when Azure Monitor recorded the row. The sensor saw the
event slightly earlier, and rows arrive in batches. Two events inside the same session that are
milliseconds apart may not sort in true order.

For anything at minute-or-coarser resolution — which is everything in this file — that's irrelevant.
For "what was the exact order of commands in this session", it matters, and the session's own
sequence in `DeviceCustomString3` is better evidence than the timestamp.

---

## 🔎 2 — `ago()`, `between()`, `startofday()`

| Want | Write |
|---|---|
| A rolling window ending now | `where TimeGenerated > ago(24h)` |
| A fixed window that excludes recent data | `where TimeGenerated between (ago(30d) .. ago(1d))` |
| Whole calendar days | `where TimeGenerated >= startofday(ago(7d))` |
| An absolute window | `where TimeGenerated between (datetime(2026-08-07) .. datetime(2026-08-09))` |

`ago()` is a rolling window. `between()` is inclusive on both ends and takes `..` between the
bounds. `startofday()` snaps to midnight **UTC**.

### `between()` earns its keep in baselines

The single most common way to write a broken hunt is a baseline that overlaps the window you're
testing. If "normal" includes today, today is normal, and the query returns nothing — which looks
exactly like a clean environment.

```kusto
// Correct: the baseline stops where the test window starts
let Baseline = CommonSecurityLog
    | where TimeGenerated between (ago(30d) .. ago(1d))   // note: NOT ago(30d)
    | summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| summarize Hits = count() by SourceIP
| join kind=leftanti Baseline on SourceIP
| order by Hits desc
```

### `startofday()` for day-over-day comparison

Rolling windows are wrong for "is today worse than usual" because `ago(1d)` at 14:00 compares a
partial day against nothing. Snap to day boundaries instead:

```kusto
// Daily honeypot volume, by door, for the last week of whole days
CommonSecurityLog
| where TimeGenerated >= startofday(ago(7d))
| summarize Events = count() by Day = startofday(TimeGenerated), DeviceVendor
| order by Day asc, Events desc
```

`startofweek()`, `endofday()`, `dayofweek()` and `hourofday()` all exist and behave the way you'd
expect.

**Everything is UTC.** The honeypot takes traffic from every timezone, so UTC is the honest frame
for it. Entra data is different — "sign-in outside business hours" needs an explicit offset, because
09:00 local is not 09:00 in `SigninLogs`:

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| extend LocalHour = hourofday(TimeGenerated + 5h30m)   // shift, then bucket
| summarize Signins = count() by LocalHour
| order by LocalHour asc
```

---

## 📦 3 — `bin()` — bucketing

`bin(TimeGenerated, 1h)` rounds each timestamp down to the start of its hour. It is what turns a pile
of rows into a shape.

```kusto
// Hourly attack volume across all four doors
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count() by Hour = bin(TimeGenerated, 1h), DeviceVendor
| render timechart
```

Two things worth knowing:

- Bins align to the **epoch**, not to your query's start time. `bin(TimeGenerated, 1d)` is therefore
  identical to `startofday(TimeGenerated)` in UTC.
- **Empty buckets do not exist.** `summarize by bin(...)` produces rows only where there was data.
  An hour with zero events is a missing row, not a zero — which means a chart will connect straight
  through an outage and hide it. `make-series` (§4) is the fix.

### Pick a bin size that matches the question

| Question | Bin |
|---|---|
| Is there a burst happening right now? | `1m` or `5m` over a few hours |
| What does a normal day look like? | `1h` over 7–14 days |
| Is this week worse than last? | `1d` over 30 days |

A 1-minute bin over 30 days is 43,200 buckets per series. That is not a chart, it's a denial of
service against your own browser.

### Bucketing plus the severity gotcha

`LogSeverity` is stored as a **string**. `LogSeverity > 7` compares text, which quietly gives wrong
answers — `"10"` sorts before `"7"`. Always `toint()` first:

```kusto
// High-severity Suricata signatures per hour
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Suricata"
| where toint(LogSeverity) >= 7        // string column -> convert before comparing
| summarize Alerts = count() by Hour = bin(TimeGenerated, 1h), Activity
| order by Hour desc, Alerts desc
```

`toint()` returns null on anything non-numeric, and a comparison against null is false — so a
malformed severity is silently dropped rather than throwing. Convenient, and worth remembering when
a count looks low.

### The budget query

`Usage` reports ingestion volume, and `Quantity` there is in **MB**. On a $15/month lab this is the
one time-series chart that decides what you can afford to keep:

```kusto
// Billable ingestion per day, per table
Usage
| where TimeGenerated > ago(14d)
| where IsBillable == true
| summarize GB = round(sum(Quantity) / 1024, 3) by Day = bin(TimeGenerated, 1d), DataType
| order by Day desc, GB desc
```

---

## 📈 4 — `make-series` and `series_decompose_anomalies`

`summarize by bin()` gives you rows. `make-series` gives you an **array per group, with a fixed shape
and no gaps** — which is what the anomaly functions need.

```kusto
// Hourly failed-login volume, as a single evenly-spaced series
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "login.failed"
| make-series Attempts = count() default=0
    on TimeGenerated from ago(14d) to now() step 1h
```

**Always give explicit `from` / `to` / `step`.** Without them the series spans only the range where
data happened to exist, so its endpoints move every time you run it — and a series whose shape
changes between runs cannot be compared to itself.

`default=0` is what makes a quiet hour a genuine zero instead of a missing point. That single word is
the difference between "the sensor was quiet" and "the sensor was dead", and the anomaly detector
needs to be able to tell those apart.

### Flagging the anomalies

```kusto
// Hourly failed logins against the honeypot, with unusual hours flagged
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor in ("sshd", "telnetd")
| where DeviceEventClassID == "login.failed"
| make-series Attempts = count() default=0
    on TimeGenerated from ago(14d) to now() step 1h
// 2.5 = how far from the baseline before we call it anomalous. Lower = more, noisier hits.
// -1  = let the function work out the seasonality itself (it will find the daily cycle).
| extend (Flag, Score, Baseline) = series_decompose_anomalies(Attempts, 2.5, -1, 'linefit')
// The series are parallel arrays; expanding them together turns them back into rows.
| mv-expand TimeGenerated to typeof(datetime),
            Attempts     to typeof(long),
            Flag         to typeof(int),
            Score        to typeof(double),
            Baseline     to typeof(double)
| where Flag != 0
| project TimeGenerated,
          Attempts,
          Expected  = round(Baseline, 1),
          Score     = round(Score, 2),
          Direction = iff(Flag > 0, "spike", "dip")   // -1 is a dip, and dips matter
| order by TimeGenerated desc
```

**A dip is a finding.** `Flag == -1` on a sensor's own volume means the sensor got quieter than its
own history predicts. That is what a dying feed looks like, and it is the single most useful thing
this function does in a small lab — the honeypot is internet-facing and takes traffic continuously,
so a quiet hour is an event, not a relief.

The Sysmon outage on the Arc-connected laptop, down since **2026-08-07**, is exactly this shape: no
error, no alert, just a volume line that stepped down and stayed there. Nothing fires when a source
stops. You have to go looking.

### The cheap version

`make-series` materialises every series in memory. One series over 14 days at 1h is 336 points and
costs nothing. **One series per `SourceIP` across a honeypot that takes continuous internet traffic
is thousands of arrays**, and will be slow or hit query limits outright.

If you want per-entity anomalies, narrow the entity set first:

```kusto
// Anomaly detection only on the IPs that matter: the ten loudest this fortnight
let Top = CommonSecurityLog
    | where TimeGenerated > ago(14d)
    | where DeviceVendor in ("sshd", "telnetd")
    | summarize Hits = count() by SourceIP
    | top 10 by Hits
    | project SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor in ("sshd", "telnetd")
| where SourceIP in (Top)          // 10 series, not thousands
| make-series Attempts = count() default=0
    on TimeGenerated from ago(14d) to now() step 1h by SourceIP
| extend (Flag, Score, Baseline) = series_decompose_anomalies(Attempts, 2.5, -1, 'linefit')
| mv-expand TimeGenerated to typeof(datetime),
            Attempts     to typeof(long),
            Flag         to typeof(int)
| where Flag > 0
| project TimeGenerated, SourceIP, Attempts
| order by Attempts desc
```

And honestly: for a lot of questions you don't need series decomposition at all. A mean and a
standard deviation over daily counts answers "is today unusual" in one pass, with no arrays:

```kusto
CommonSecurityLog
| where TimeGenerated >= startofday(ago(14d))
| where DeviceVendor in ("sshd", "telnetd")
| summarize Events = count() by Day = startofday(TimeGenerated)
| summarize Today   = anyif(Events, Day == startofday(now())),
            AvgDay  = round(avg(Events), 1),
            StdDev  = round(stdev(Events), 1)
```

Reach for `series_decompose_anomalies` when the data has a **cycle** you'd otherwise flag as noise —
the honeypot's daily rhythm, Entra's working-week shape. If there's no cycle, the simpler query is
the better query.

---

## ⏳ 5 — Durations with `datetime_diff`

Two ways to measure elapsed time, and they return different things:

| Expression | Returns | Use for |
|---|---|---|
| `EndTime - StartTime` | a `timespan` | display, and anything sub-second |
| `datetime_diff('second', EndTime, StartTime)` | an `int` | maths, thresholds, sorting |

`datetime_diff(unit, end, start)` gives `end - start`, and **truncates to whole units** — a 0.4
second gap measured in `'second'` is `0`. Get the argument order backwards and every duration comes
out negative, which is at least an obvious failure.

Valid units: `'second'`, `'minute'`, `'hour'`, `'day'`, `'week'`, `'month'`, `'quarter'`, `'year'`.

### How long was each honeypot session?

`DeviceCustomString1` carries the sshd session id, which is what makes per-session maths possible:

```kusto
// Session length and activity, per honeypot session
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("sshd", "telnetd")
| where isnotempty(DeviceCustomString1)
| summarize SessionStart = min(TimeGenerated),
            SessionEnd   = max(TimeGenerated),
            Commands     = countif(DeviceEventClassID == "command.input"),
            Downloads    = countif(DeviceEventClassID == "session.file_download"),
            Uploads      = countif(DeviceEventClassID == "session.file_upload"),
            LoggedIn     = countif(DeviceEventClassID == "login.success") > 0,
            SourceIP     = any(SourceIP)
        by SessionId = DeviceCustomString1
| extend DurationSec = datetime_diff('second', SessionEnd, SessionStart)
| where Commands > 0                      // sessions that did nothing aren't interesting yet
| order by DurationSec desc
```

This measures first-logged to last-logged event, which is a **lower bound** on the real session
length — a session still open right now looks short, and one that idled after its last command looks
shorter than it was. Say that out loud when you report a number from it.

### Time from login to first command

The gap between a successful login and the first typed command separates a human from a script.
Scripts are fast and consistent; people pause.

```kusto
// Dwell time between a successful login and the first command in that session
let Logins = CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceEventClassID == "login.success"
    | summarize LoginTime = min(TimeGenerated),
                SourceIP  = any(SourceIP),
                User      = any(DestinationUserName)
            by SessionId = DeviceCustomString1;
let FirstCommand = CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceEventClassID == "command.input"
    | summarize FirstCmdTime = min(TimeGenerated),
                FirstCmd     = take_any(DeviceCustomString3)
            by SessionId = DeviceCustomString1;
Logins
| join kind=inner FirstCommand on SessionId
| extend Gap        = FirstCmdTime - LoginTime,                          // timespan, keeps sub-second
         GapSeconds = datetime_diff('second', FirstCmdTime, LoginTime)   // int, for thresholds
| project SessionId, SourceIP, User, LoginTime, Gap, GapSeconds, FirstCmd
| order by GapSeconds asc      // fastest first — the automated ones
```

Both forms are there on purpose. `Gap` is what you paste into a ticket; `GapSeconds` is what you put
a `< 2` filter on.

### Age of anything

`now()` as the end of a `datetime_diff` turns a timestamp into an age, which is how you check whether
a feed is still alive:

```kusto
// How stale is each source that should be reporting continuously?
union isfuzzy=true
    (CommonSecurityLog | where TimeGenerated > ago(7d) | summarize Last = max(TimeGenerated) | extend Source = "CommonSecurityLog"),
    (SecurityEvent     | where TimeGenerated > ago(7d) | summarize Last = max(TimeGenerated) | extend Source = "SecurityEvent"),
    (Syslog            | where TimeGenerated > ago(7d) | summarize Last = max(TimeGenerated) | extend Source = "Syslog"),
    (Heartbeat         | where TimeGenerated > ago(7d) | summarize Last = max(TimeGenerated) | extend Source = "Heartbeat"),
    (SigninLogs        | where TimeGenerated > ago(7d) | summarize Last = max(TimeGenerated) | extend Source = "SigninLogs"),
    (AppServiceHTTPLogs| where TimeGenerated > ago(7d) | summarize Last = max(TimeGenerated) | extend Source = "AppServiceHTTPLogs")
| extend AgeMinutes = datetime_diff('minute', now(), Last)
| project Source, Last, AgeMinutes
| order by AgeMinutes desc
```

Named tables rather than `union *` — `union *` touches every table in the workspace and is the
easiest way to write a slow query by accident. `isfuzzy=true` keeps the whole thing from failing if
one table has no rows in range.

---

## 🆕 6 — First seen — new, or always been here?

This is the question that makes an IP address mean something. The same address is a nuisance if it
has been knocking for three weeks and an incident if it showed up ninety minutes ago.

### The verdict query

One pass over the table, and it answers both halves of the question — *when* did this first appear,
and *is it still here*:

```kusto
// Every source IP seen in the last 24h, judged against its own history in the workspace
let Retention  = 30d;           // workspace default; nothing older than this exists to compare to
let RecentWin  = 24h;
let Recent = CommonSecurityLog
    | where TimeGenerated > ago(RecentWin)
    | summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(Retention)
| where SourceIP in (Recent)                     // only score IPs that are active right now
| summarize FirstSeen  = min(TimeGenerated),
            LastSeen   = max(TimeGenerated),
            TotalHits  = count(),
            HitsRecent = countif(TimeGenerated > ago(RecentWin)),
            DaysActive = dcount(startofday(TimeGenerated)),   // seen on how many distinct days
            Doors      = make_set(DeviceEventCategory, 5),
            Users      = make_set(DestinationUserName, 10)
        by SourceIP
| extend AgeDays = datetime_diff('day', now(), FirstSeen)
| extend Verdict = case(
        AgeDays >= 29, "Long-standing — at the retention edge, may well be older",
        AgeDays >= 7,  "Established — known for over a week",
        AgeDays >= 1,  "Recent — first appeared in the last few days",
                       "NEW — first ever record is inside the last 24h")
| project SourceIP, Verdict, FirstSeen, LastSeen, AgeDays, DaysActive, TotalHits, HitsRecent, Users, Doors
| order by AgeDays asc, HitsRecent desc
```

**Read the `AgeDays >= 29` bucket carefully.** Workspace retention is 30 days. An IP whose first
record is 29 days old is not proven to be old — it is proven to be *at least* that old, because there
is nothing behind it to look at. First-seen in KQL always means **first seen within retention**, and
saying otherwise in a ticket is a claim the data cannot support.

`DaysActive` is what separates the two flavours of "old": an IP seen on 28 distinct days is
background noise, and an IP first seen 25 days ago but active on only 2 of them is somebody who came
back.

### The strict version

When you want only the genuinely new and nothing else, `leftanti` against an explicitly
non-overlapping baseline:

```kusto
// Source IPs in the last 24h with no record at all in the preceding 29 days
let Baseline = CommonSecurityLog
    | where TimeGenerated between (ago(30d) .. ago(1d))    // must not overlap the test window
    | summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| summarize FirstSeen = min(TimeGenerated),
            Hits      = count(),
            Failed    = countif(DeviceEventClassID == "login.failed"),
            Success   = countif(DeviceEventClassID == "login.success"),
            Doors     = make_set(DeviceEventCategory, 5)
        by SourceIP
| join kind=leftanti Baseline on SourceIP
| order by Success desc, Hits desc      // a brand-new IP that logged in successfully goes to the top
```

### Which one to use

| | Verdict query | `leftanti` query |
|---|---|---|
| Table scans | one | two |
| Tells you *when* | yes | only within the recent window |
| Tells you *whether* it's new | yes, with nuance | yes, binary |
| Good for | triage, judgement | a feed into something automated |

Prefer the single-pass version when a person is reading the output. It costs one scan instead of two
and it answers a richer question. Use `leftanti` when you need a clean yes/no list with nothing to
interpret.

### First-seen works on anything, not just IPs

Swap the `by` key and the same shape answers a different question:

```kusto
// Usernames the attackers have started trying only recently
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DeviceVendor in ("sshd", "telnetd")
| where isnotempty(DestinationUserName)
| summarize FirstSeen = min(TimeGenerated), Attempts = count(), Sources = dcount(SourceIP)
        by DestinationUserName
| where FirstSeen > ago(3d)          // vocabulary that is new to this honeypot
| order by Attempts desc
```

New usernames appearing in bulk means a new wordlist, which usually means a new tool or a new actor.
The same pattern works on `Activity` for Suricata signature names, on `DeviceCustomString3` for
commands, and on `AppServiceHTTPLogs` for paths on the decoy site.

### One trap specific to this workspace

`DeviceEventCategory` — the Door label — was **added on 2026-08-22**. Rows ingested before that date
do not carry it. So a first-seen query keyed on `DeviceEventCategory` over a 30-day window will
report every door as brand new, because the *column* is new, not the sensor.

This generalises: **a first-seen query cannot distinguish a new thing from a newly-logged thing.**
Before believing a first-seen result, ask what changed in the pipeline on that date.

---

## 💸 7 — What actually costs money

Worth being precise, because the folklore here is wrong in both directions.

**Queries against normal Analytics tables are not billed per query.** In this workspace you pay for
ingestion and retention. Running a badly-written query fifty times does not appear on the invoice.

What a heavy query actually costs you:

- **Time and timeouts.** Queries have hard limits on duration, result size, and memory.
  `make-series` across thousands of series hits the memory ceiling and fails outright.
- **Silent detection failure.** A rule whose query sits near the limit doesn't get slower — it
  starts failing, and a failing analytics rule produces exactly as many incidents as a rule that
  found nothing. That is the expensive one.

What genuinely does bill:

| Thing | Billed how |
|---|---|
| Ingestion | per GB — see the `Usage` query in §3 |
| Retention past the 30-day default | per GB-month |
| Search jobs and archive restore | per job / per GB scanned |
| Queries against Basic or Auxiliary tier tables | per GB **scanned** |

That last row is the one that turns §1 from good practice into arithmetic. Analytics-tier tables
don't charge per scan; Basic and Auxiliary tiers do. If a high-volume table is ever moved to a
cheaper tier to protect the $15/month budget, a missing time filter becomes a line item.

**And the free win:** queries reaching past 30 days return nothing, because nothing is there. They
still take time to run and still look like a clean result. `ago(90d)` against this workspace is not a
long lookback, it's a bug.

---

## ⚠️ 8 — Gotchas

**A baseline overlapping the test window returns nothing.** Use `between (ago(30d) .. ago(1d))`, not
`ago(30d)`. Symptom: a clean-looking environment.

**`summarize by bin()` omits empty buckets.** A chart drawn from it interpolates straight through an
outage. Use `make-series ... default=0` when absence is the signal.

**`make-series` without explicit `from`/`to`** produces a series whose endpoints move between runs,
so it can't be compared to itself.

**`LogSeverity` is a string.** So is Suricata's priority in `DeviceCustomString1`. Wrap in `toint()`
before comparing, or `"10"` sorts below `"7"`.

**`datetime_diff` truncates.** Sub-second gaps in `'second'` come out as `0`. Subtract the datetimes
instead when precision matters.

**`datetime_diff(unit, end, start)`** — end first. Backwards gives negative durations.

**Everything is UTC.** `startofday()`, `bin()`, `hourofday()` all snap to UTC. Shift explicitly
before you talk about anyone's working hours.

**First seen means first seen within retention.** 30 days here. An IP at the retention edge is *at
least* that old, not *exactly* that old.

**A new column looks exactly like a new source.** `DeviceEventCategory` arrived 2026-08-22; anything
keyed on it will read as new across the older part of the window.

**`union *` is expensive.** Name the tables. `isfuzzy=true` keeps a union alive when one table is
empty in range.

**Don't leave `ago()` in an analytics rule.** The rule's `queryPeriod` already scopes it, and the
intersection is rarely what was intended.

**Sysmon on the Arc-connected laptop has been down since 2026-08-07.** Any endpoint time series
crossing that date has a step in it that is an outage, not a change in attacker behaviour. Check
before drawing a conclusion from it.

---

## What to learn next

- `../summarize/` — the aggregations these time buckets are built on
- `../performance/` and `../optimization/` — the rest of the cost story
- `../threat-hunting/` — where first-seen queries turn into hypotheses
- [Hunting guide](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/08-hunting.md)
  — turning a repeated hunt into one of the 38 rules

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Roadmap](../../README.md)
