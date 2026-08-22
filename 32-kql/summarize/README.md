# Summarize — aggregation in depth

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Area](https://img.shields.io/badge/Area-summarize-0078D4?style=flat-square)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)

> Every query here runs against **this lab's own workspace** (`la-lab-eus-01`) and the tables that
> actually hold data. Nothing below is a generic textbook example — the columns are the columns the
> honeypot really writes.

Back to the [KQL module map](../README.md) &nbsp;·&nbsp;
the deployed rules are in the [detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).

---

## 🎯 Why summarize is most of the job

The honeypot is internet-facing and takes real attacker traffic continuously. That means
`CommonSecurityLog` is never a list you can read — it is a firehose. An analyst who only knows
`where` and `project` can answer "show me the failed logins," which returns thousands of rows and
tells you nothing.

`summarize` is the operator that turns a firehose into a finding. It collapses many rows into one
row per *thing you care about* — per attacker, per username, per hour, per port. Almost every
useful question in this workspace is really a grouping question:

- Which IPs are hitting us hardest? → group by `SourceIP`
- Is this a targeted attack or a broad sweep? → count distinct `DestinationPort` per IP
- Is this actor new, or have they been here for weeks? → `min()` and `max()` of `TimeGenerated`
- What did they actually type? → collect `DeviceCustomString3` per session

Of the 38 analytics rules deployed in this lab, the large majority end in a `summarize`. Learn this
operator properly and detection engineering stops being mysterious.

---

## 🧱 The anatomy of a summarize

Start with the smallest possible real query — what is each sensor contributing?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count() by DeviceVendor
```

Three sensors feed this table, so you get at most three rows back: `sshd` (or `telnetd`), `Suricata`
and `nftables`. That single query is the fastest orientation check in the workspace — if a vendor is
missing from the output, that sensor stopped reporting.

**The one thing that surprises everybody:** after `summarize`, the only columns that still exist are
the ones you named — your group keys plus your aggregates. `SourceIP`, `Activity`, `TimeGenerated`
and everything else are *gone*. This fails:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count() by DeviceVendor
| where SourceIP == "1.2.3.4"     // ERROR: SourceIP no longer exists at this point
```

Filter **before** you summarize, or carry the column through as a group key or an aggregate. This is
not a quirk — it is the whole point. Summarize is a funnel, and anything you did not explicitly ask
to keep falls out of it.

You can also rename in the `by` clause, which is worth doing whenever the raw column name is
meaningless on its own:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| summarize Commands = count() by SessionId = DeviceCustomString1   // DCS1 is the session id for sshd
| order by Commands desc
```

And `summarize` with **no** `by` at all collapses the entire result to a single row — useful for a
quick total:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize TotalEvents = count(), UniqueSources = dcount(SourceIP)
```

---

## 🔢 Counting: count, countif, dcount

Three functions that beginners treat as interchangeable and that answer completely different
questions.

| Function | Question it answers |
|---|---|
| `count()` | How many rows? |
| `countif(predicate)` | How many rows matched *this condition*? |
| `dcount(expr)` | How many **distinct values** of this column? |

### countif — several counts in one scan

The naive approach is to run the same query four times with a different `where` each time. That
scans the table four times and gives you four numbers you then have to line up by hand. `countif`
does it in one pass:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| summarize
    AllEvents     = count(),
    Connects      = countif(DeviceEventClassID == "session.connect"),
    Failed        = countif(DeviceEventClassID == "login.failed"),
    Succeeded     = countif(DeviceEventClassID == "login.success"),
    CommandsTyped = countif(DeviceEventClassID == "command.input"),
    Downloads     = countif(DeviceEventClassID == "session.file_download")
  by SourceIP
| extend SuccessRate = round(100.0 * Succeeded / (Failed + Succeeded), 1)   // 100.0 forces float division
| order by CommandsTyped desc, AllEvents desc
```

That one query is a triage board. An IP with 400 failures and zero successes is a bot spraying
credentials. An IP with 3 failures, 1 success and 20 commands typed is a human being who got in —
and that is the row you work first.

Note `100.0 * ...` rather than `100 * ...`. Integer division in KQL truncates, so
`100 * 1 / 3` gives `33` while `100.0 * 1 / 3` gives `33.33...`. Use a float literal whenever you
want a rate.

### dcount — cardinality, and the fact that it is approximate

`dcount()` does not count distinct values exactly. It uses a HyperLogLog estimate, which is why it
stays fast and cheap on very large columns. It takes an optional accuracy argument from `0` to `4`;
the default is `1`, which is accurate to roughly a percent. Level `4` is the most accurate and the
most memory-hungry.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd"
| summarize
    ApproxDefault = dcount(SourceIP),        // accuracy level 1 (default)
    ApproxHigh    = dcount(SourceIP, 4),     // slower, tighter estimate
    Exact         = count_distinct(SourceIP) // exact, and the most expensive of the three
```

**When does the difference matter?** Almost never for triage — "about 1,400 unique attackers" and
"1,412 unique attackers" lead to the same decision. It matters when the number is the *detection
logic itself*. A rule that fires at "more than 20 distinct ports" sitting right on the threshold
should use `count_distinct()`, because you do not want an estimator deciding whether an incident
exists. For dashboards and hunting, `dcount()` every time.

There is also `dcountif()`, which is the obvious combination and saves you a subquery:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| summarize
    UsernamesTried    = dcount(DestinationUserName),
    UsernamesThatWorked = dcountif(DestinationUserName, DeviceEventClassID == "login.success")
  by SourceIP
| where UsernamesThatWorked > 0
```

---

## 📐 The numeric family: min, max, avg, sum

### min and max on time — the first/last seen pair

This is the single most reused aggregation in SOC work and it gets its own section further down,
but the mechanic is trivial: `min(TimeGenerated)` is when you first saw the thing, `max(TimeGenerated)`
is when you last saw it.

### The LogSeverity trap

`LogSeverity` in this table is a **string**, not a number. `max()` on a string sorts
lexicographically, so `"9"` ranks above `"10"`. This is the highest-value gotcha in the whole
schema, and the failure is silent — you get a plausible-looking answer that is wrong.

Prove it to yourself:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| summarize
    StringMax  = max(LogSeverity),          // WRONG: text sort, "9" beats "10"
    NumericMax = max(toint(LogSeverity))    // RIGHT: numeric sort
```

Then do it properly. Convert once with `extend`, then aggregate:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| extend Severity = toint(LogSeverity)      // convert once, up front
| summarize
    Alerts        = count(),
    HighestSeen   = max(Severity),
    LowestSeen    = min(Severity),
    AvgSeverity   = round(avg(Severity), 2),
    Sources       = dcount(SourceIP)
  by SignatureName = Activity                // Activity holds the Suricata signature name
| order by Alerts desc
```

Confirm which direction your sensor maps severity before you read anything into `max()` — CEF
severity and Suricata's own priority field do not point the same way, and this lab carries the
Suricata priority separately in `DeviceCustomString1`. Aggregating a number you have not checked the
meaning of is how a dashboard ends up confidently backwards.

### avg lies, percentiles do not

`avg()` is the aggregate people reach for and the one that misleads most often, because a single
burst drags the mean. When you want to know what *normal* looks like, ask for percentiles:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd"
| summarize EventsPerHour = count() by bin(TimeGenerated, 1h)
| summarize
    Mean   = round(avg(EventsPerHour), 1),
    Median = percentile(EventsPerHour, 50),
    P95    = percentile(EventsPerHour, 95),
    Peak   = max(EventsPerHour)
```

If `Mean` sits well above `Median`, the traffic is bursty and you should be alerting on bursts, not
on daily totals.

### sum — and the only aggregation that touches the bill

`CommonSecurityLog` has no natural quantity column in this lab, so `sum()` gets used mostly for
cost. `_BilledSize` is present on every Log Analytics table and is the per-record billed bytes:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize
    Rows     = count(),
    TotalMB  = round(sum(_BilledSize) / 1024.0 / 1024.0, 2),   // bytes -> MB
    AvgBytes = round(avg(_BilledSize), 0)
  by DeviceVendor
| order by TotalMB desc
```

On a $15/month budget this is not academic. If one sensor is producing most of the megabytes, that
sensor is where a filter at the source buys you the most headroom. The workspace-wide version of the
same question:

```kusto
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize BillableMB = round(sum(Quantity), 1) by DataType   // Quantity is already in MB
| order by BillableMB desc
```

---

## 🧺 Collecting values: make_set and make_list

Counts tell you *how much*. Sets and lists tell you *what*. This is the difference between "that IP
tried 340 logins" and "that IP tried `root`, `admin`, `oracle`, `postgres` and `ubuntu`."

| Function | Duplicates | Order | Use for |
|---|---|---|---|
| `make_set(expr, cap)` | removed | not meaningful | which distinct values appeared |
| `make_list(expr, cap)` | kept | input order, best-effort | a sequence of events |

### The size cap, and why you should always pass one

Both functions take an optional second argument capping the number of elements collected. The
default is **1,048,576** elements and you cannot raise it above that. Separately, the resulting
dynamic cell is subject to the query's result-size limits, so an unbounded `make_set` over a busy
column can produce enormous cells, slow the query down, or fail it outright.

In SOC queries you almost never want a million elements — you want a *sample* big enough to
recognise the pattern. Pass a small explicit cap and move on:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize
    Attempts  = count(),
    Usernames = make_set(DestinationUserName, 50),    // DCS2 is the password, DestinationUserName the user
    Passwords = make_set(DeviceCustomString2, 50),
    FirstTry  = min(TimeGenerated),
    LastTry   = max(TimeGenerated)
  by SourceIP
| extend UsernameCount = array_length(Usernames)
| order by Attempts desc
| take 25
```

Reading the credential lists directly is the fastest way to classify a bot. A set of
`root`/`admin`/`test` is commodity spray. A set containing your actual application account names is
something else entirely, and worth an incident.

### make_list when the order is the evidence

Reconstructing what an attacker typed is a `make_list` job, because duplicates and sequence both
matter. Sort the input first — `make_list` preserves the order it receives rows in, and it only
receives them in a useful order if you asked for one:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| sort by DeviceCustomString1 asc, TimeGenerated asc     // order the input before collapsing it
| summarize
    Commands  = make_list(DeviceCustomString3, 200),     // DCS3 is the command typed
    FirstCmd  = min(TimeGenerated),
    LastCmd   = max(TimeGenerated)
  by SessionId = DeviceCustomString1, SourceIP
| extend CommandCount = array_length(Commands)
| extend SessionSeconds = datetime_diff("second", LastCmd, FirstCmd)
| order by CommandCount desc
```

**Treat that ordering as best-effort.** It is reliable enough to read a session and understand the
actor's intent, which is what you want it for. If the exact sequence is going to be *evidence* —
something you would put in a report or hand to someone else — do not collapse the rows at all. Keep
them and sort them, the way the deployed command-execution rule does.

### The _if variants

`make_set_if` and `make_list_if` filter while collecting, which saves you from splitting the query
in two:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| summarize
    TotalCommands = count(),
    DownloadAttempts = make_set_if(DeviceCustomString3,
                                   DeviceCustomString3 has_any ("wget", "curl", "tftp"), 25),
    Sessions = dcount(DeviceCustomString1)
  by SourceIP
| where array_length(DownloadAttempts) > 0     // only actors who tried to pull a payload
| order by TotalCommands desc
```

---

## 🏁 arg_max and arg_min — the latest row per X

This is the aggregation that unlocks a whole class of questions, and the one most people never
learn.

`max(TimeGenerated)` gives you a **timestamp**. It does not tell you anything else about the row
that timestamp came from — the username, the command, the action. `arg_max(TimeGenerated, ...)`
gives you **the row itself**.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd"
| summarize arg_max(TimeGenerated, *) by SourceIP      // the whole most-recent row, per IP
| project TimeGenerated, SourceIP, DeviceEventClassID, DestinationUserName, Activity
| order by TimeGenerated desc
```

`*` brings every column through. The maximised column keeps its own name, and the `by` key is not
duplicated. If you only need a few columns, list them instead of `*` and the output columns keep
their original names:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DeviceVendor == "sshd"
| summarize arg_max(TimeGenerated, DeviceEventClassID, DestinationUserName, Activity) by SourceIP
| order by TimeGenerated desc
```

That answers **"what was the last thing each attacker did?"** — the current state of every actor,
one row each. Flip to `arg_min` for **"what was the first thing they did?"**, which is how you find
the entry point:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where isnotempty(SourceIP)
| summarize arg_min(TimeGenerated, DeviceVendor, DeviceEventClassID, DestinationPort) by SourceIP
| order by TimeGenerated desc
```

If first contact came from `nftables` or `Suricata`, they found the host by scanning. If it came
straight from `sshd`, they arrived already knowing the service was there — which is a different and
more interesting story.

### Two things to know about arg_max

1. **It skips nulls.** Rows where the maximised expression is null are ignored. With `TimeGenerated`
   that never bites, but it will if you ever `arg_max` on a sparse column.
2. **You cannot put `arg_max(T, *)` and `arg_min(T, *)` in the same summarize** — the output column
   names collide. When you want both ends, use `min()`/`max()` for the timestamps and a separate
   `arg_max` for the row detail.

### The version you will run every morning

Agent health, in four lines. `arg_max` here means you get the last heartbeat *and its details*, not
just its time:

```kusto
Heartbeat
| where TimeGenerated > ago(24h)
| summarize arg_max(TimeGenerated, *) by Computer
| extend MinutesStale = datetime_diff("minute", now(), TimeGenerated)
| project Computer, LastSeen = TimeGenerated, MinutesStale, Category, Version
| order by MinutesStale desc
```

`arg_max` is also the standard way to **deduplicate**: when a table holds repeated rows per entity
and you only want the newest state of each, `summarize arg_max(TimeGenerated, *) by <entity>` is the
idiom.

If you genuinely do not care *which* row you get — you just need one sample value — `take_any()` is
cheaper than forcing `arg_max` to sort.

---

## ⏱️ bin() — time bucketing

`bin()` rounds a value down to the nearest multiple. On a datetime that means time buckets, and
grouping by a bucket is how you turn a pile of events into a shape.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
| render timechart
```

Pick the bucket to match the question. `1m` finds bursts. `1h` finds working patterns. `1d` finds
trends. Too small and you get noise; too large and you flatten the thing you were looking for.

**`bin(x, 1d)` buckets on UTC midnight.** The workspace is UTC, so a "day" here is not your day. When
you correlate a spike against something that happened locally, this is where the hour offset creeps
in. `bin_at()` lets you anchor buckets to a point you choose — a shift start, for instance:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor == "sshd"
// buckets run 08:00-to-08:00 rather than midnight-to-midnight
| summarize Events = count() by ShiftDay = bin_at(TimeGenerated, 1d, datetime(2026-08-01 08:00:00))
| order by ShiftDay desc
```

### The empty-bucket trap

`summarize` only emits buckets that contain rows. An hour with **zero** events does not produce a
zero — it produces nothing at all. Rendered as a timechart, the line jumps straight across the gap,
and a sensor outage looks like a quiet period.

That matters here specifically: this honeypot takes traffic continuously, so an hour with no events
is a *finding*, not a lull. `make-series` is the fix, because it fills the gaps:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| make-series Events = count() default = 0
    on TimeGenerated from ago(24h) to now() step 1h    // default = 0 materialises the empty hours
| render timechart
```

Use `summarize ... by bin()` when you want a table you will read. Use `make-series` when you want a
line you will trust.

---

## 🧬 Multi-level grouping

Add more columns to `by` and you get one row per combination. Two levels is the everyday case:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count() by DeviceVendor, DeviceEventClassID
| order by DeviceVendor asc, Events desc
```

That is the whole sensor picture on one screen — what each door is seeing, broken out by event type.
Run it first when something feels off.

Three levels, adding time, shows you how that picture moves:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count() by bin(TimeGenerated, 1h), DeviceVendor, DeviceEventClassID
| order by TimeGenerated desc, Events desc
```

**Group keys multiply.** One row per combination that actually occurred means
`by SourceIP, DestinationPort, bin(TimeGenerated, 1m)` against a busy honeypot can produce an
enormous result. Add keys deliberately, and check the row count before you add a fourth.

Also worth noticing what *not* to group by. `Computer` is always `db-finance-prod01` — there is one
host — so `by Computer` adds a column and no information. And `DeviceCustomString1` means three
different things depending on vendor (session id for `sshd`, priority for `Suricata`, interface for
`nftables`), so grouping by it without filtering `DeviceVendor` first mixes three unrelated value
spaces into one column.

### Summarizing twice

The technique that earns its complexity: aggregate, then aggregate the aggregate. Here it turns
"how much traffic" into "how *bursty* is this actor" — which is what separates a slow persistent
scanner from a brute-force run:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd"
// level 1: how many events did each IP generate in each hour?
| summarize EventsThisHour = count() by SourceIP, bin(TimeGenerated, 1h)
// level 2: describe each IP's hourly behaviour across the week
| summarize
    PeakHour     = max(EventsThisHour),
    AvgPerHour   = round(avg(EventsThisHour), 1),
    ActiveHours  = count(),                      // counts level-1 rows = hours with any activity
    TotalEvents  = sum(EventsThisHour)
  by SourceIP
| extend Burstiness = round(PeakHour / AvgPerHour, 1)   // how far the worst hour sits above typical
| where TotalEvents > 50
| order by Burstiness desc
```

Note what `count()` means at level 2: it counts *rows produced by level 1*, and each of those rows is
one hour. So `ActiveHours` is genuinely "hours in which this IP did anything." Keeping track of what
a row represents at each stage is the entire skill here.

### Check a column before you group by it

`DeviceEventCategory` was added to this pipeline on **2026-08-22**. Group by it across 30 days and
most of your output lands in one empty bucket, because the column did not exist for most of that
window. Before trusting any grouping on a newer column, measure its coverage:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)
| summarize
    Rows          = count(),
    Populated     = countif(isnotempty(DeviceEventCategory)),
    FirstPopulated = minif(TimeGenerated, isnotempty(DeviceEventCategory))
| extend PercentPopulated = round(100.0 * Populated / Rows, 1)
```

Once you have scoped the range to where the column is actually populated, it is the clearest view of
the layered design in the whole table — which door caught what:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1d)                      // stay inside the window where this column exists
| where isnotempty(DeviceEventCategory)
| summarize
    Events   = count(),
    Sources  = dcount(SourceIP),
    Denied   = countif(DeviceAction == "Denied")
  by DeviceEventCategory, DeviceVendor
| order by DeviceEventCategory asc, Events desc
```

---

## 🔎 The classic SOC shapes

Three patterns you will write for the rest of your career. Learn them as shapes, not as queries.

### Shape 1 — Events per source IP

The starting point for every honeypot triage. One row per attacker, ranked.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(SourceIP)
| summarize
    Events       = count(),
    Denied       = countif(DeviceAction == "Denied"),
    SeenBy       = make_set(DeviceVendor, 5),        // which sensors saw this IP
    PortsTouched = dcount(DestinationPort),
    LastSeen     = max(TimeGenerated)
  by SourceIP
| order by Events desc
| take 25
```

The `SeenBy` column is the one to read first. An IP seen by **one** sensor is background noise. An IP
seen by `nftables` *and* `Suricata` *and* `sshd` walked the full path from packet to shell, and that
is a real attack chain in three columns.

### Shape 2 — First seen / last seen

The shape that answers "is this new?" — which is usually the first thing anyone asks about an
indicator.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)              // retention is 30 days; ago(90d) returns nothing extra
| where isnotempty(SourceIP)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated),
    Events    = count()
  by SourceIP
| extend ActiveHours = round(datetime_diff("second", LastSeen, FirstSeen) / 3600.0, 1)
| extend IsNewToday  = FirstSeen > ago(1d)    // never seen before today
| order by LastSeen desc
```

**The caveat that matters:** `FirstSeen` is bounded by retention. An IP whose `FirstSeen` sits right
at the 30-day edge was probably not first seen then — that is just as far back as this workspace can
still see. Never report "first observed" from a query whose window equals your retention without
saying so.

The same shape pointed at your own telemetry is how dead sensors announce themselves:

```kusto
SecurityEvent
| where TimeGenerated > ago(30d)
| summarize
    Events    = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated)
  by EventID
| order by LastSeen asc      // stalest event IDs float to the top - that is the point
```

Sysmon on the Arc-connected laptop has been down since **2026-08-07**. A rule watching for Sysmon
event IDs stayed green and enabled that entire time, because a rule that finds nothing looks
identical to a rule with nothing to find. This query is the difference.

### Shape 3 — Distinct ports probed

Port sweeps are a cardinality question, not a volume question. An IP that hits one port 5,000 times
is brute-forcing. An IP that hits 500 ports once each is mapping you.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "nftables"        // the firewall sees the sweep the shell never will
| where isnotempty(SourceIP) and isnotempty(DestinationPort)
| summarize
    DistinctPorts = dcount(DestinationPort),
    Attempts      = count(),
    PortSample    = make_set(DestinationPort, 40),    // a sample, not every port
    Denied        = countif(DeviceAction == "Denied"),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
  by SourceIP
| extend SweepSeconds = datetime_diff("second", LastSeen, FirstSeen)
| extend PortsPerMinute = round(DistinctPorts / (SweepSeconds / 60.0), 1)   // speed separates tool from human
| where DistinctPorts >= 10               // a threshold turns a report into a detection
| order by DistinctPorts desc
```

`PortsPerMinute` is the useful derived column. A few ports a minute is someone poking. Hundreds a
minute is `masscan`, and the response is different.

The same cardinality logic on the decoy website finds path enumeration instead of port enumeration —
same shape, different noun:

```kusto
AppServiceHTTPLogs
| where TimeGenerated > ago(24h)
| summarize
    Requests   = count(),
    Errors     = countif(toint(ScStatus) >= 400),   // toint() is harmless if already int, saves you if not
    DistinctPaths = dcount(CsUriStem),
    PathSample = make_set(CsUriStem, 15)
  by CIp
| where DistinctPaths > 20                          // one client, many distinct paths = enumeration
| order by DistinctPaths desc
```

### The same shapes on identity and storage

Aggregation shapes are portable. Failed-login-rate per user in Entra is Shape 1 with different
column names — and note that `ResultType` is another string that looks like a number:

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| summarize
    Attempts  = count(),
    Failures  = countif(ResultType != "0"),      // ResultType is a STRING; "0" means success
    SourceIPs = dcount(IPAddress),
    LastSeen  = max(TimeGenerated)
  by UserPrincipalName
| extend FailureRate = round(100.0 * Failures / Attempts, 1)
| where Attempts > 5
| order by FailureRate desc, Attempts desc
```

And on blob storage, where the interesting aggregate is deletes per caller:

```kusto
StorageBlobLogs
| where TimeGenerated > ago(7d)
| summarize
    Operations = count(),
    Deletes    = countif(OperationName == "DeleteBlob"),
    OpTypes    = make_set(OperationName, 20),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated)
  by CallerIpAddress
| order by Deletes desc, Operations desc
```

---

## 💸 Cost and efficiency

Worth being precise about what actually costs money here, because the usual advice is vague.

Every table listed in this lab is on the **Analytics** tier, and running an interactive query against
an Analytics table does not add to the $15. You pay for ingestion and retention, not for asking
questions. So a slow query does not bill you — it costs you *time*, and it risks hitting the
platform limits (a query times out after 10 minutes, and results are capped at 500,000 rows / 64 MB;
`summarize` usually keeps you far under both, which is part of why it is the right tool).

Two places where efficiency does turn into real cost:

1. **Scheduled analytics rules.** A rule query does not run once, it runs on a timer — every 5
   minutes for the fastest rules in this lab. With 38 rules deployed, a wasteful rule query runs
   hundreds of times a day. This is the genuine reason to care.
2. **Basic or Auxiliary tier tables.** If a table is ever moved off Analytics to save on ingestion,
   queries against it *are* billed per GB scanned. Aggregating a Basic-tier table over 30 days is a
   line item.

The habits that matter, in order of impact:

| Habit | Why |
|---|---|
| `where TimeGenerated > ago(...)` first, always | Time is the primary partition. Nothing else narrows the scan as hard |
| Then filter `DeviceVendor` / `DeviceEventClassID` | Cheap string equality on high-selectivity columns, before any work |
| `summarize` before `join`, not after | Aggregating first shrinks both sides — the deployed scan-then-login rule does exactly this |
| Cap every `make_set` / `make_list` | Unbounded dynamic cells are the most common cause of a slow summarize here |
| `dcount()` over `count_distinct()` unless exactness is the logic | Estimator is dramatically cheaper on high-cardinality columns |
| Never `project` columns you then discard | Fewer columns through the pipeline is less to move |

The thing to internalise: **`summarize` runs after the scan.** It reduces what comes *out*, not what
goes *in*. Putting `| take 10` after a summarize does not make the query cheaper — the whole scan
already happened. Only `where` makes a query cheap, and only when it is early.

For genuinely high-cardinality groupings you can hint the engine to distribute the work:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize hint.shufflekey = SourceIP Events = count() by SourceIP, DestinationPort
```

Reach for that when a `by` on a very wide key is slow. At this lab's data volume it rarely changes
anything, and reaching for it before the ordinary filters are right is a way of avoiding the actual
problem.

---

## ⚠️ Traps specific to this workspace

| Trap | What you see | Fix |
|---|---|---|
| `max(LogSeverity)` | `"9"` outranks `"10"` — silently wrong | `max(toint(LogSeverity))` |
| `by Computer` | Always `db-finance-prod01` | Drop it — there is one host |
| `by DeviceCustomString1` across vendors | Session ids, Suricata priorities and interface names mixed in one column | Filter `DeviceVendor` first |
| `by DeviceEventCategory` over 30d | One huge empty bucket | Column landed 2026-08-22 — scope the window |
| `ago(90d)` | Same rows as `ago(30d)` | Retention is 30 days |
| `bin()` + `render timechart` | Outages look like quiet periods | `make-series ... default = 0` |
| Uncapped `make_set` | Slow query, giant cells, sometimes failure | Pass an explicit cap |
| `FirstSeen` at the 30-day edge | Reads as "first ever seen" | It is the retention boundary — say so |
| Sysmon `EventID`s absent from `SecurityEvent` | A green rule that never fires | Down since 2026-08-07 — check with first/last seen |
| `100 * Failures / Attempts` | Truncated integer, `0` instead of `0.4` | Use `100.0` |

---

## 📋 Quick reference

| Function | Returns | Reach for it when |
|---|---|---|
| `count()` | Rows in the group | Volume |
| `countif(pred)` | Rows matching the predicate | Several counts in one scan |
| `dcount(expr [, 0-4])` | Approximate distinct count | Cardinality — unique IPs, unique ports |
| `dcountif(expr, pred)` | Approximate distinct, filtered | Unique users who also failed |
| `count_distinct(expr)` | Exact distinct count | The number *is* the detection threshold |
| `min()` / `max()` | Smallest / largest | First seen / last seen |
| `minif()` / `maxif()` | Same, filtered | First time a condition held |
| `avg()` / `sum()` | Mean / total | Rates, and `_BilledSize` for cost |
| `percentile(expr, N)` | Nth percentile | What "normal" is, when `avg` is dragged by bursts |
| `make_set(expr, cap)` | Deduped array | Which usernames / ports / vendors appeared |
| `make_list(expr, cap)` | Ordered array, duplicates kept | A sequence — commands in a session |
| `make_set_if` / `make_list_if` | Filtered versions | Only the download commands |
| `arg_max(expr, *)` | The whole row with the largest expr | Latest state per entity; deduplication |
| `arg_min(expr, *)` | The whole row with the smallest expr | First contact per entity |
| `take_any(expr)` | An arbitrary value from the group | You genuinely do not care which row |
| `bin(col, span)` | Value floored to a multiple | Time buckets |
| `bin_at(col, span, anchor)` | Floored to a chosen origin | Buckets aligned to a shift, not UTC midnight |
| `make-series ... default = 0` | A gap-filled series | Charts where absence is a finding |

---

## ✅ Practice

Work these against the live workspace. Each one is a real question, not a syntax drill.

- [ ] For the last 24 hours, produce one row per `SourceIP` with total events, failed logins,
      successful logins and distinct usernames tried. Sort by successes.
- [ ] Find every IP seen by **all three** sensors in the last 7 days. (Hint: `make_set(DeviceVendor)`
      then `array_length`.)
- [ ] For the busiest attacker session, reconstruct the command sequence in order.
- [ ] Chart failed logins per hour for 24 hours using `make-series`, and identify any hour with
      genuinely zero activity.
- [ ] Using `arg_max`, list the last action taken by each of the top 20 attackers.
- [ ] Using `arg_min`, work out which sensor saw each attacker *first* — and what proportion arrived
      via a scan versus straight to the service.
- [ ] Find IPs whose peak hour was more than 10× their average hour (the two-level summarize).
- [ ] Rank sensors by `sum(_BilledSize)` and decide which one you would filter at the source first.
- [ ] Run the coverage check on `DeviceEventCategory` and state, in one sentence, what window it is
      safe to group by.
- [ ] Take any rule from the [detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
      and name which of these shapes it is built from.

---

[← KQL module](../README.md) &nbsp;·&nbsp; [Roadmap](../../README.md) &nbsp;·&nbsp; [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
