# 32.02 — KQL Operators

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Area](https://img.shields.io/badge/Area-operators-0078D4?style=flat-square)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)

> Every query in this file runs against **la-lab-eus-01**, this lab's real Sentinel workspace.
> No sample tables, no invented columns. Paste them into **Sentinel → General → Logs** and they work.

Most of the queries lean on `CommonSecurityLog`, the CEF feed from **db-finance-prod01** — the
internet-facing honeypot. It is the richest table in this workspace because it takes real attacker
traffic continuously, which means every operator below has something real to chew on.

---

## 🧭 The eight operators, one line each

Learn these eight and you can read roughly ninety percent of the queries in the
[detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).

| Operator | What it does to your rows | What it does to your columns |
|---|---|---|
| `where` | keeps only rows that match | nothing |
| `project` | nothing | keeps *only* the columns you name |
| `project-away` | nothing | drops the columns you name, keeps the rest |
| `project-rename` | nothing | renames columns, keeps everything |
| `extend` | nothing | **adds** a new calculated column |
| `distinct` | collapses duplicates | keeps only the columns you name |
| `take` / `limit` | keeps *any* N rows | nothing |
| `top` | keeps the N **highest/lowest** rows | nothing |
| `order by` / `sort by` | reorders | nothing |
| `count` | collapses everything to one row | replaces them with a single `Count` |
| `search` | keeps rows matching text *anywhere* | nothing |

The mental model that makes KQL click: **a query is a pipeline.** Each `|` hands its result to the
next stage. You start with the widest thing you have — a table name — and every stage after that
should make the data smaller, narrower, or better-shaped. If a stage makes things *bigger*, ask why.

---

## 💸 What a sloppy query actually costs here

Worth being precise, because "queries cost money" gets repeated carelessly.

On the **Analytics** tier — the default tier, and where the tables in this lab's day-to-day work
live — Log Analytics bills you for **ingestion and retention**, not for running a query. Running
`CommonSecurityLog` with no filter does not add a line to the invoice.

What a bad query costs you instead:

| Cost | Why it bites |
|---|---|
| **Time** | An unfiltered scan over 30 days of honeypot CEF takes far longer than the same query scoped to `ago(1h)`. |
| **Timeouts** | The Logs blade cuts queries off. A query that can't finish is worth nothing regardless of price. |
| **Real billing on other tiers** | Tables on the **Basic** or **Auxiliary** tier *are* billed per GB scanned. Habits built on Analytics follow you there. |
| **Multiplied by schedule** | A wasteful query in a scheduled analytics rule doesn't run once — it runs every 5 minutes, forever. There are **38 analytics rules** deployed here. |

On a **$15/month** budget, the discipline matters more than the arithmetic. Two rules cover most of it:

1. **Filter on time first.** `where TimeGenerated > ago(...)` is the cheapest filter you own, because
   the data is partitioned by time. Put it at the top of every query.
2. **Narrow before you widen.** Filter and project *before* you extend, join, or sort.

> **Retention here is 30 days.** `ago(60d)` is not expensive — it is simply empty. If a query
> returns nothing, check your time window against retention before you assume the data is missing.

---

## 🔎 `where` — keep the rows that matter

**What it does:** filters rows. It is the operator you will type more than all the others combined,
and it is where nearly all of your query performance is won or lost.

### Real question: which usernames are attackers trying against the fake SSH shell?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)          // time first, always — cheapest possible filter
| where DeviceVendor == "sshd"            // the fake shell, not Suricata or nftables
| where DeviceEventClassID == "login.failed"
| project TimeGenerated, SourceIP, Username = DestinationUserName, PasswordTried = DeviceCustomString2
| order by TimeGenerated desc
```

Chaining several small `where` stages instead of one long `and` is a style choice, not a performance
one — the engine treats them identically. Separate lines are easier to comment and easier to comment
*out* while you are debugging, which is why the detection library is written that way.

### Pick the right string operator

This is the single highest-leverage habit in this whole page.

| Operator | Matches | Speed |
|---|---|---|
| `==` | the whole value, exactly | fastest |
| `has` | a whole **term** (word) inside the value | fast — uses the term index |
| `contains` | any **substring**, term or not | slow — no index |
| `startswith` / `endswith` | anchored substring | middling |

Hunting for download attempts inside typed commands:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any ("wget", "curl", "tftp")   // has_any = term match, index-backed
| project TimeGenerated, SourceIP, SessionId = DeviceCustomString1, Command = DeviceCustomString3
```

`has_any` matches whole terms, so it finds `wget http://...` but will not fire on an unrelated
substring the way `contains "wget"` would. Reach for `contains` only when you genuinely need to match
mid-word — and know you have given up the index to do it.

### The `LogSeverity` trap

In this workspace `LogSeverity` arrives as a **string**, not a number. String comparison sorts
`"10"` before `"9"`, so comparing it raw gives silently wrong answers.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| where toint(LogSeverity) >= 7          // convert BEFORE comparing, or "10" < "9" bites you
| project TimeGenerated, SourceIP, DestinationPort, Signature = Activity, LogSeverity
```

Note the ordering: the `TimeGenerated` and `DeviceVendor` filters sit **above** the `toint()` filter.
A conversion wrapped around a column means the engine cannot use that column's index, so you want the
cheap indexed filters to have already shrunk the row set before it runs.

### ❌ When *not* to use `where`

- **After `summarize` when it could go before.** Filtering 4 aggregated rows instead of 400,000 raw
  ones feels efficient but is backwards — you already paid to aggregate the rows you then threw away.
- **On a column you just computed, when a raw column would do.** `where toint(LogSeverity) >= 7` is
  necessary. `where tostring(SourceIP) == "..."` is not — filter the raw column.
- **As a substitute for a time filter.** `where SourceIP == "..."` with no `TimeGenerated` bound still
  scans the full 30-day retention window.

---

## ✂️ `project`, `project-away`, `project-rename` — control the columns

`CommonSecurityLog` has dozens of columns and this lab populates maybe fifteen of them. The `project`
family is how you stop scrolling sideways past forty empty fields.

### `project` — keep only these columns

**What it does:** keeps exactly the columns you name, in the order you name them, and drops
everything else. It renames inline too.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| project
    TimeGenerated,
    AttackerIP = SourceIP,                 // rename inline: NewName = OldName
    SessionId  = DeviceCustomString1,
    Command    = DeviceCustomString3
```

Renaming at the `project` stage is not cosmetic. `DeviceCustomString3` tells a reader nothing;
`Command` tells them everything. Every rule in the detection library projects the custom-string
columns into readable names for exactly this reason — the analyst reading the incident at 2am did not
memorise the CEF field mapping.

### `project-away` — drop these, keep the rest

**What it does:** the inverse. Useful when you want *most* columns and only need a few gone.

For `nftables` rows, the sshd-specific fields are always empty — they are simply not part of a
firewall event:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "nftables"
| project-away DeviceCustomString2, DeviceCustomString3, DestinationUserName  // sshd-only, empty here
```

It accepts wildcards, which is handy against a table this wide:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Suricata"
| project-away DeviceCustomNumber*, DeviceCustomDate*, Flex*   // clear out unused CEF extension slots
```

### `project-rename` — rename without dropping anything

**What it does:** renames columns and leaves every other column untouched, in place.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "sshd"
| project-rename
    SessionId     = DeviceCustomString1,
    PasswordTried = DeviceCustomString2,
    Command       = DeviceCustomString3
```

This is the right operator while you are still **exploring** — you get readable names for the fields
you understand so far, without committing to a final column list you might regret two stages later.

### ❌ When *not* to use the `project` family

- **`project` too early in an exploration.** It is destructive downstream: a column you dropped in
  stage two cannot be referenced in stage six. Explore with `project-rename`, commit with `project`.
- **`project-away` when you only want five columns.** Naming five keepers is clearer than naming
  thirty-five rejects, and it survives schema changes — if a new CEF field appears tomorrow,
  `project` ignores it while `project-away` silently lets it through.
- **`project` where you meant `extend`.** `project` drops everything you did not name. If you want
  the original columns *plus* a new one, that is `extend`.
- **Projecting away a join key** before a join. Very common, very confusing to debug.

---

## ➕ `extend` — add a calculated column

**What it does:** computes a new column and appends it, keeping every existing column. This is where
parsing, type conversion, and derived values live.

### Real question: which high-priority Suricata signatures are firing, and what are their IDs?

Suricata packs `gid:signature_id` into `DeviceEventClassID` (e.g. `"1:2024897"`) and its priority
into `DeviceCustomString1`. Neither is directly usable — `extend` makes them so:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"                                    // filter on raw columns first
| extend Priority    = toint(DeviceCustomString1)                     // Suricata puts priority here
| extend SignatureId = tostring(split(DeviceEventClassID, ":")[1])    // "1:2024897" -> "2024897"
| where Priority == 1                                                 // 1 = most severe in Suricata
| project TimeGenerated, SourceIP, DestinationPort, SignatureId, Signature = Activity, Priority
| order by TimeGenerated desc
```

The ordering here is deliberate and worth internalising: **`DeviceVendor` and `TimeGenerated` are
filtered before the `extend` stages.** `extend` runs once per surviving row, so every row you remove
beforehand is arithmetic you never pay for. Filtering on `Priority` has to come after, because the
column does not exist until `extend` creates it.

### `extend` also relabels — and that is a legitimate use

The `DeviceEventCategory` column records which sensor in the traffic path saw the event
(`"Door 2 - Host Firewall"`, `"Door 3 - Network IDS/IPS - <cat>"`, `"Door 4 - Application Shell (SSH)"`).
When it is absent you can derive an equivalent from the vendor:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| extend Door = case(
    DeviceVendor == "nftables",              "Door 2 - Host Firewall",
    DeviceVendor == "Suricata",              "Door 3 - Network IDS/IPS",
    DeviceVendor in ("sshd", "telnetd"),     "Door 4 - Application Shell",
    "Unknown")                                // case() needs a final default, or it errors
| summarize Events = count() by Door
| order by Events desc
```

> ⚠️ `DeviceEventCategory` was **added on 2026-08-22**. Rows ingested before that date do not carry
> it. A query filtering on it across `ago(30d)` will only return rows from the day it was added
> onward — that is not a broken query, it is the field's actual history.

### ❌ When *not* to use `extend`

- **Above your filters.** `extend` before `where` computes a value for every row you were about to
  discard. Push filters up.
- **For a value you use once and drop.** If it only exists to be filtered on and never appears in the
  output, inline the expression into the `where` and skip the column.
- **When you meant to rename.** `extend Command = DeviceCustomString3` leaves *both* columns in the
  result. That is `project-rename`'s job.
- **To fake a column that isn't there.** Deriving `Door` above is fine because it is honestly labelled
  as derived. Do not `extend` a plausible-looking value and then treat it as ingested evidence.

---

## 🎯 `distinct` — one row per unique combination

**What it does:** returns the unique combinations of the columns you name, dropping everything else.

### Real question: how many different IPs are attacking, and which usernames is each one trying?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| distinct SourceIP
```

Name more than one column and you get unique *combinations*, not each column's uniques separately:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| distinct SourceIP, DestinationUserName        // unique PAIRS: one row per IP+username seen
| order by SourceIP asc
```

That second query is a genuinely useful triage view — it turns thousands of brute-force rows into a
compact "who tried what" list, which is usually the shape you actually want.

### `distinct` vs `summarize by`

They deduplicate identically. The difference is what else you get:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
          by SourceIP, DestinationUserName      // same dedupe as distinct, but you keep the numbers
| order by Attempts desc
```

Use `distinct` when you want the **list**. Use `summarize ... by` the moment you want the list *and*
a count, a first-seen, or anything else alongside it.

### ❌ When *not* to use `distinct`

- **When the next question is "how many times?"** You will immediately rewrite it as `summarize`.
  Skip the round trip.
- **On high-cardinality columns over a wide window.** `distinct` must hold every unique value it has
  seen in memory. `distinct SourceIP, SourcePort` over 30 days of honeypot traffic is close to
  one-row-per-event and can blow up — `SourcePort` is essentially random per connection.
- **As a way to hide a bad join.** Duplicate rows after a join usually mean the join key is not as
  unique as you assumed. `distinct` papers over that; it does not fix it.

---

## 🎲 `take` vs `limit` vs `top` — the one people get wrong

`take` and `limit` are **exact synonyms**. Same operator, two spellings, zero behavioural difference.
Pick one and be consistent; this lab writes `take`.

`top` is a genuinely different operator, and confusing the two produces conclusions that are wrong
rather than merely slow.

### `take` — give me any N rows, fast

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "sshd"
| take 10                          // ANY 10 matching rows — no ordering promised, may differ per run
```

`take` returns whichever N rows the engine finds first. It can stop the moment it has enough, without
looking at the rest of the data. That makes it cheap — and **non-deterministic**: run it twice and you
may get different rows, even with no new data arriving.

Its correct use is *shape-checking*. You are asking "does this query return the columns I expect, with
values that look sane?" — not "what is in this data?"

### `top` — give me the N highest, correctly

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| summarize Attempts = count() by SourceIP     // collapse to one row per IP first
| top 10 by Attempts desc                      // now rank — cheap, because only IPs remain
```

`top N by Col` is equivalent to `sort by Col | take N`, but it states intent and lets the engine keep
just an N-sized heap instead of ordering everything.

Here is the part that matters: **`top` must see every matching row.** It cannot know which ten IPs are
noisiest until it has counted all of them. `take` can quit early; `top` cannot. That is the whole cost
difference, and it is why the query above runs `summarize` *first* — ranking 200 aggregated IP rows is
trivial, ranking 200,000 raw event rows is not.

### Side by side

| | `take N` / `limit N` | `top N by Col` |
|---|---|---|
| Which rows come back | any N the engine finds first | the N highest/lowest by `Col` |
| Order guaranteed | ❌ no | ✅ yes |
| Same rows on a re-run | ❌ not guaranteed | ✅ yes (barring ties or new data) |
| Work done | can stop early — **cheap** | must evaluate every matching row |
| Honest use | peeking, shape-checking | answers, reports, "worst offenders" |

### ❌ When *not* to use them

- **Never draw a conclusion from `take`.** "I ran `take 100` and saw no successful logins, so there
  were none" is unsound — you sampled arbitrary rows, not representative ones. This is the mistake
  that matters; the rest are style.
- **Never put `take` in an analytics rule.** A detection that arbitrarily discards matching rows will
  miss real attacks, silently and unpredictably.
- **Don't reach for `top` when peeking.** If you just want to see what the columns look like, `take`
  is cheaper and equally informative.
- **Don't `top` raw events when you meant to rank groups.** `top 10 by TimeGenerated` on raw rows
  gives you the ten most recent events, which is often *not* the "top 10 attackers" you wanted.

---

## ↕️ `order by` / `sort by` — put rows in a deliberate order

**What it does:** sorts the result set. `order by` and `sort by` are **exact synonyms**, like
`take`/`limit`. Default direction is `desc` if you omit it, but write it explicitly — future-you
should not have to remember.

### Real question: what were the most recent successful logins to the honeypot?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.success"
| project TimeGenerated, SourceIP, Username = DestinationUserName, SessionId = DeviceCustomString1
| order by TimeGenerated desc                  // newest first — the default for investigation
```

Sort by several keys, and control where empty values land:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| extend Priority = toint(DeviceCustomString1)
| project TimeGenerated, SourceIP, Priority, Signature = Activity
| order by Priority asc, TimeGenerated desc nulls last   // priority 1 first; blanks pushed to bottom
```

`nulls last` is worth knowing. Rows where `toint()` failed to parse become null, and by default they
can sort to the top and crowd out the results you actually wanted to read.

**Sorting is a blocking stage.** Unlike `where`, it cannot stream — the engine has to materialise the
whole result set before it can emit the first row. That is why it belongs near the *end* of a
pipeline, after the filters and aggregations have made the set small.

### ❌ When *not* to use `order by`

- **Before `summarize`.** Aggregation ignores input order entirely. You paid to sort rows that were
  about to be collapsed. Sort the *output* instead.
- **In a scheduled analytics rule.** The rule engine does not care what order your rows are in. It is
  pure cost, repeated on every run — and with 38 rules deployed, that adds up.
- **As a substitute for `top`.** `sort by X desc | take 10` works, but `top 10 by X desc` says what
  you mean and is the idiom other analysts expect.
- **On a full unfiltered table.** Sorting 30 days of CEF to look at ten rows is the most expensive way
  to answer a cheap question.

---

## 🔢 `count` — how many rows?

**What it does:** collapses the entire result set into a single row with one column, `Count`. Note
there are no parentheses — `| count` is an *operator*, distinct from `count()`, the aggregation
*function* used inside `summarize`.

### Real question: is this filter even matching anything before I build the rest of the query?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.failed"
| count
```

This is `count`'s best everyday use: a **sizing check**. Before you write a forty-line hunting query,
spend one line confirming the base filter matches a sane number of rows. If it returns 0, your filter
is wrong — find that out now, not after building on top of it.

### `count` vs `summarize count()`

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| summarize Events = count() by DeviceEventClassID     // the BREAKDOWN, not the grand total
| order by Events desc
```

That returns one row per event class — `session.connect`, `login.failed`, `login.success`,
`command.input`, `session.file_download`, `session.file_upload` — which tells you the shape of
attacker behaviour. `| count` would have flattened all of it into one uninformative number.

| You want | Use |
|---|---|
| One grand total | `\| count` |
| A total per group | `\| summarize count() by <col>` |
| How many *unique* values | `\| summarize dcount(<col>)` |

### ❌ When *not* to use `count`

- **When the interesting answer is a breakdown.** A single number rarely resolves an investigation.
  "4,812 failed logins" means little; "4,812 from one IP against one username" is an incident.
- **When you want unique values, not rows.** That is `dcount()`, or `distinct` then `count`.
- **As a substitute for looking at the data.** A non-zero count confirms rows exist. It says nothing
  about whether they are the rows you meant to match.

---

## 🔦 `search` — full-text across columns (handle with care)

**What it does:** matches a term against **every column**, without you naming any of them. It is the
one operator on this page with a genuine "be careful" label.

### Real question: this IP showed up in an incident — where else does it appear?

```kusto
search in (CommonSecurityLog, Syslog) "203.0.113.45"   // TEST-NET placeholder: swap in a real IP
| where TimeGenerated > ago(24h)                       // scope the time, ALWAYS
| project TimeGenerated, Type, SourceIP, DestinationIP, Activity
| take 50
```

Note `in (CommonSecurityLog, Syslog)`. **Always scope `search` to named tables.** A bare
`search "203.0.113.45"` queries *every table in the workspace* — Entra sign-ins, AzureActivity,
StorageBlobLogs, AppServiceHTTPLogs, Heartbeat, all of it — over your whole time range.

### 💸 The cost warning, stated plainly

`search` cannot use the term index the way `where ... has` can, because it does not know which column
to look in. It reads far more data than an equivalent `where`. On the Analytics tier that costs you
time and risks a timeout; on a **Basic or Auxiliary** tier table, scanned volume is **billed**, and an
unscoped `search` over 30 days is exactly the query that turns a $15 month into a surprise.

Once you know which column the value lives in — and after one `search` you usually do — rewrite it:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SourceIP == "203.0.113.45"        // indexed, exact, and dramatically cheaper
| project TimeGenerated, DeviceVendor, DeviceEventClassID, DestinationPort, Activity
| order by TimeGenerated desc
```

Same answer. A fraction of the work. **`search` is a discovery tool; `where` is the finished query.**

### ❌ When *not* to use `search`

- **Never in an analytics rule.** Unindexed, wide, and running on a schedule is the worst possible
  combination. None of the 38 deployed rules use it.
- **Never unscoped.** If you type `search`, type `in (...)` in the same breath.
- **Not when you know the column.** `where SourceIP == "..."` is strictly better in every dimension.
- **Not for exploring a schema.** To learn what a table holds, `take 10` and read the columns, or
  check `getschema` — don't full-text search for it.

---

## 🧪 Putting it together

One realistic triage query using most of the page. The question: **over the last 24 hours, which
source IPs got furthest into the honeypot — and what did they type?**

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)                        // 1. time first
| where DeviceVendor == "sshd"                          // 2. the application shell only
| where DeviceEventClassID in ("login.success", "command.input")   // 3. got in, or acted
| project-rename
    SessionId = DeviceCustomString1,
    Command   = DeviceCustomString3                     // 4. readable names, nothing dropped yet
| summarize
    Logins    = countif(DeviceEventClassID == "login.success"),
    Commands  = countif(DeviceEventClassID == "command.input"),
    Sessions  = dcount(SessionId),
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated),
    SampleCommands = make_set(Command, 10)              // 5. up to 10 distinct commands per IP
  by SourceIP
| where Commands > 0                                    // 6. drop IPs that logged in but did nothing
| top 20 by Commands desc                               // 7. rank AFTER aggregating — cheap here
```

Read the stage numbers back and notice the shape: filters at the top where they cost least, renaming
before aggregation so the aggregate is readable, and the ranking at the very end where only one row
per IP remains. That ordering is the entire lesson of this page.

`countif()` and `make_set()` belong to the `summarize` area — they are here to show *where* the
operators you have just learned sit in a real query, not to be explained yet.

---

## ⚠️ Workspace gotchas that will bite you

| Gotcha | What to do |
|---|---|
| `LogSeverity` is a **string** | Wrap it in `toint()` before any `>`, `<`, or `>=` comparison. |
| `DeviceEventCategory` added **2026-08-22** | Rows older than that date do not have it. Not a bug. |
| Retention is **30 days** | `ago(60d)` returns nothing. Check the window before assuming data loss. |
| Sysmon on the Arc laptop **down since 2026-08-07** | `SecurityEvent` is thin after that date. Don't read the gap as "no activity." |
| `DeviceCustomString1/2/3` mean **different things per vendor** | Session/password/command for `sshd`; priority for Suricata; interface for nftables. Always filter `DeviceVendor` first. |
| `Syslog` holds the same events as raw text | Use it to reconstruct a session during investigation. Detections belong on `CommonSecurityLog`. |

---

## ✅ Self-check

You have this area when you can, without looking anything up:

- [ ] Explain why `take 50` is a bad way to prove something *didn't* happen
- [ ] State the difference between `project`, `project-away`, and `project-rename` in one sentence each
- [ ] Say why `extend` belongs below your `where` stages, not above
- [ ] Choose between `distinct` and `summarize ... by` and justify it
- [ ] Rewrite a `search` into an equivalent `where`, and say what you saved
- [ ] Explain why `| count` and `count()` are not the same thing
- [ ] Write a query for "top 10 attacking IPs in the last 24h" with the `top` in the right place

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md) &nbsp;·&nbsp; [Hunting guide](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/HOWTO-GUIDES/08-hunting.md)
