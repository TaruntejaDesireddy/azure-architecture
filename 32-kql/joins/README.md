# 32 — KQL · Joins

**Workspace:** `la-lab-eus-01` &nbsp;·&nbsp; **Primary table:** `CommonSecurityLog`
**Supporting:** `Syslog`, `SecurityEvent`, `Heartbeat`
**Prerequisite:** `where` / `summarize` / `project` — joins assume you can already shape one table.

> Joins are the part of KQL where a mistake does not throw an error. It returns a table.
> The table looks fine. The numbers in it are wrong.
>
> Every other operator fails loudly — misspell a column and the query dies. A join with the
> wrong `kind=` runs perfectly and silently drops or multiplies rows. That is why this area
> gets its own document, and why almost all of it is about *which rows survive*.

---

## Contents

1. [The five kinds at a glance](#-the-five-kinds-at-a-glance)
2. [Prove the semantics to yourself in 20 seconds](#-prove-the-semantics-to-yourself-in-20-seconds)
3. [innerunique — the default, and why it surprises people](#-innerunique--the-default-and-why-it-surprises-people)
4. [inner — every match, including the multiplied ones](#-inner--every-match-including-the-multiplied-ones)
5. [The habit that removes the whole problem](#-the-habit-that-removes-the-whole-problem)
6. [The lab's real cross-source correlation](#-the-labs-real-cross-source-correlation)
7. [leftouter — keep every left row, enrich where you can](#-leftouter--keep-every-left-row-enrich-where-you-can)
8. [leftanti — "in A but not B"](#-leftanti--in-a-but-not-b)
9. [fullouter — nobody gets dropped](#-fullouter--nobody-gets-dropped)
10. [union — when you just want rows stacked](#-union--when-you-just-want-rows-stacked)
11. [Join or union? One question](#-join-or-union-one-question)
12. [Cost and efficiency in this workspace](#-cost-and-efficiency-in-this-workspace)
13. [Gotchas that produce wrong answers silently](#-gotchas-that-produce-wrong-answers-silently)
14. [Practice](#-practice)

---

## 🔎 The five kinds at a glance

A join takes a **left** table (whatever is piping in) and a **right** table (the operand), and
matches them on a key. The `kind=` decides what happens to rows that match more than once, and
to rows that match nothing at all.

| `kind=` | Which rows come back | Which columns come back | Reach for it when |
|---|---|---|---|
| `innerunique` | matches only, **left side deduplicated by key first** | both sides | never on purpose — it is just the default |
| `inner` | matches only, all of them, multiplied | both sides | you want the true set of matched pairs |
| `leftouter` | **every** left row; right columns filled where matched | both sides | enrichment — keep the population, add detail |
| `leftanti` | left rows with **no** match on the right | **left only** | "in A but not B" — absence, new things, gaps |
| `fullouter` | everything from both sides | both sides | comparing two sources for coverage |

Two more worth knowing, same family:

| `kind=` | Which rows come back |
|---|---|
| `leftsemi` | left rows that **do** have a match — left columns only (the mirror of `leftanti`) |
| `rightanti` | right rows with no match on the left |

The two that cause the most damage are the top two, because they look identical in the editor.

---

## 🔎 Prove the semantics to yourself in 20 seconds

Before touching real data, run this. It is self-contained — a `datatable` is a literal, it
queries nothing and costs nothing, and it pins down the exact behaviour that the rest of this
document depends on.

```kusto
// Paste this anywhere. It touches no workspace data.
let leftSide = datatable(SourceIP:string, Note:string)
[
    "10.0.0.1", "firewall hit 1",
    "10.0.0.1", "firewall hit 2",   // SAME key as the row above - this is the whole point
    "10.0.0.2", "firewall hit 3"    // this key has no partner on the right
];
let rightSide = datatable(SourceIP:string, User:string)
[
    "10.0.0.1", "root",
    "10.0.0.1", "admin"             // the right side has duplicate keys too
];
leftSide
| join rightSide on SourceIP        // no kind= at all - this is innerunique
| count
```

Now swap the `join` line for each `kind=` in turn. Three left rows and two right rows produce
five different answers:

| `join` line | Rows back | Why |
|---|--:|---|
| `join rightSide on SourceIP` | 2 | left deduped to one `10.0.0.1` row, then × 2 right rows |
| `join kind=inner rightSide on SourceIP` | 4 | 2 left `10.0.0.1` rows × 2 right rows |
| `join kind=leftouter rightSide on SourceIP` | 5 | the 4 matches, plus `10.0.0.2` with an empty `User` |
| `join kind=leftanti rightSide on SourceIP` | 1 | only `10.0.0.2` — the row with no partner |
| `join kind=fullouter rightSide on SourceIP` | 5 | the 4 matches plus `10.0.0.2`; nothing is right-only here |

Read the first two rows of that table again. **Same query, same data, one keyword, double the
count.** Neither version errors.

---

## 🔎 innerunique — the default, and why it surprises people

Write `| join X on Y` with no `kind=` and you get `kind=innerunique`. What it does:

1. It **deduplicates the left side by the join key** — keeps one row per distinct key value.
2. *Then* it performs an inner join.

Which left row survives step 1 is not something you should rely on. The others are discarded
before the join ever happens.

Three consequences that bite in a SOC:

**Your counts are wrong, not empty.** If the left side is 4,000 firewall rows across 30 IPs, the
join sees 30 rows. Any `count()`, `sum()`, or `dcount()` you do afterwards is describing 30 rows
while you believe it is describing 4,000.

**Only the left is deduplicated.** Duplicates on the *right* still multiply normally. So the
result is neither "one row per key" nor "all pairs" — it is a hybrid that matches no mental model
anyone has.

**The result is never larger than `kind=inner`, so it looks conservative and safe.** A quieter
number reads like a tighter query. It is a truncated one.

Here is the trap on real lab data. Both queries below are legitimate-looking. Run both.

```kusto
let firewall =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceVendor == "nftables"          // many rows per attacker IP
    | project SourceIP, FirewallTime = TimeGenerated, FirewallAction = DeviceAction;
let shell =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "session.connect"
    | project SourceIP, ShellTime = TimeGenerated;
firewall
| join shell on SourceIP                        // <-- no kind=. innerunique. left is deduped.
| summarize MatchedRows = count(), IPs = dcount(SourceIP)
```

```kusto
// Identical apart from one keyword.
let firewall =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceVendor == "nftables"
    | project SourceIP, FirewallTime = TimeGenerated, FirewallAction = DeviceAction;
let shell =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceVendor == "sshd" and DeviceEventClassID == "session.connect"
    | project SourceIP, ShellTime = TimeGenerated;
firewall
| join kind=inner shell on SourceIP             // <-- every firewall row, every shell row
| summarize MatchedRows = count(), IPs = dcount(SourceIP)
```

`IPs` will agree. `MatchedRows` will not, and the first query's number will be the smaller of the
two — that follows directly from the dedup step, not from anything about today's traffic.

**The rule to internalise:** if you did not type `kind=`, you did not choose a join. Always type
it, even when you want `innerunique`, so the next person can see that you meant it.

---

## 🔎 inner — every match, including the multiplied ones

`kind=inner` is the honest inner join: every left row paired with every matching right row. If an
IP has 200 firewall rows and 15 sshd rows, you get 3,000 rows for that IP alone.

That is correct behaviour, and it is usually not what you wanted. Row counts after an unaggregated
`kind=inner` are a **product**, not a population. Anyone who then writes `| summarize count() by
SourceIP` and calls it "events per attacker" is reporting a multiplication.

Use raw `kind=inner` when you genuinely want the pairs — for example, every denied firewall attempt
paired with every later allowed connection from the same IP, so you can measure the gap between
them:

```kusto
let denied =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceAction == "Denied"
    | project SourceIP, DeniedTime = TimeGenerated, DeniedPort = DestinationPort;
let allowed =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceAction == "Allowed"
    | where DestinationPort in (22, 23, 2222, 2223)
    | project SourceIP, AllowedTime = TimeGenerated, AllowedPort = DestinationPort;
denied
| join kind=inner allowed on SourceIP           // pairs are the point here, not a population
| where AllowedTime > DeniedTime                // order matters: probe first, then connect
| where AllowedTime - DeniedTime < 1h
| extend MinutesToStrike =
        round(datetime_diff('second', AllowedTime, DeniedTime) / 60.0, 1)
| summarize Attempts = count(), Fastest = min(MinutesToStrike) by SourceIP
| order by Fastest asc
```

Here the fan-out is deliberate — each pair is a real (probe, connection) combination, and the
`summarize` at the end collapses it back down to one row per IP.

---

## 🔎 The habit that removes the whole problem

**Aggregate each side to one row per join key before you join.** Once both sides are unique on
the key, `innerunique` and `inner` return identical results, and the entire class of bug
disappears.

Three ways to get there:

| Technique | Use when |
|---|---|
| `summarize ... by SourceIP` | you want counts, first/last seen, sets of values |
| `distinct SourceIP` | you only need the key itself — the cheapest option |
| `summarize arg_max(TimeGenerated, *) by SourceIP` | you want the single most recent full row per key |

This is not a stylistic preference. Every join in the rest of this document does it, and so does
the deployed rule in the next section.

---

## 🔎 The lab's real cross-source correlation

This is the shape worth memorising, and the reason `CommonSecurityLog` is the richest table here:
**one table holds two independent layers of evidence about the same attacker.**

The honeypot is internet-facing and takes real traffic continuously. An attacker passes through
sensors in order, and `DeviceEventCategory` names each sensor's position in that path:

| Door | `DeviceEventCategory` | `DeviceVendor` | What it proves |
|---|---|---|---|
| 2 | `Door 2 - Host Firewall` | `nftables` | the packet reached the host |
| 3 | `Door 3 - Network IDS/IPS - <cat>` | `Suricata` | the traffic matched a signature |
| 4 | `Door 4 - Application Shell (SSH)` | `sshd`, `telnetd` | a service actually handled it |

An IP seen at Doors 2/3 **and** Door 4 within a short window is a full progression: found the
host, then tried to get in. Two independent sources, one narrative. This is the correlation
behind one of the 38 deployed analytics rules — the library is at
[`DETECTIONS/README.md`](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).

```kusto
let lookback = 24h;
// Network layer: Suricata and nftables both see traffic before any service handles it.
let networkLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DeviceVendor in ("Suricata", "nftables")
    | where isnotempty(SourceIP)
    | summarize NetworkEvents    = count(),
                FirstNetworkSeen = min(TimeGenerated),
                Sensors          = make_set(DeviceVendor),
                PortsTouched     = dcount(DestinationPort),
                DeniedCount      = countif(DeviceAction == "Denied")
            by SourceIP;                        // one row per IP - fan-out impossible
// Application layer: only reached if something got past the network layer.
let appLayer =
    CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DeviceVendor == "sshd"
    | summarize ShellEvents      = count(),
                FirstConnectSeen = min(TimeGenerated),
                UsersTried       = dcount(DestinationUserName),
                LoginSuccess     = countif(DeviceEventClassID == "login.success"),
                CommandsTyped    = countif(DeviceEventClassID == "command.input")
            by SourceIP;                        // also one row per IP
networkLayer
| join kind=inner appLayer on SourceIP          // both sides unique on the key, so inner
                                                // and innerunique agree - stated explicitly
| extend Computer = "db-finance-prod01"         // summarize dropped it; the honeypot is one host
| extend SecondsNetworkToShell =
        datetime_diff('second', FirstConnectSeen, FirstNetworkSeen)
| project SourceIP, Computer, Sensors, NetworkEvents, DeniedCount, PortsTouched,
          ShellEvents, UsersTried, LoginSuccess, CommandsTyped,
          FirstNetworkSeen, FirstConnectSeen, SecondsNetworkToShell
| order by SecondsNetworkToShell asc
```

`SecondsNetworkToShell` is the interesting column. A very small value suggests automation that
scans and logs in as one motion; a large one suggests the scan and the login came from different
stages, or different operators, reusing the same address.

**A note on `DeviceEventCategory`.** It was added on 2026-08-22. Filtering or joining on it
excludes everything ingested before that date, and workspace retention is 30 days — so for most
of the retained window it is empty. Use `DeviceVendor` for anything that needs to reach back;
treat `DeviceEventCategory` as the friendly label for recent data.

---

## 🔎 leftouter — keep every left row, enrich where you can

`kind=leftouter` answers a different question from `inner`. Not *"which IPs did both layers
see?"* but *"here is my full population — for each one, did the other layer see it too?"*

The population is preserved. That is the point. Use it when the denominator matters.

```kusto
// Every IP the network layer saw, annotated with what the shell saw - including the ones
// the shell never saw at all.
let shellActivity =
    CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceVendor == "sshd"
    | summarize ShellEvents  = count(),
                LoginSuccess = countif(DeviceEventClassID == "login.success"),
                FirstShell   = min(TimeGenerated)
            by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("Suricata", "nftables")
| where isnotempty(SourceIP)
| summarize NetworkEvents = count(), PortsTouched = dcount(DestinationPort) by SourceIP
| join kind=leftouter shellActivity on SourceIP  // keep ALL network IPs, matched or not
// Unmatched numeric columns come back null; unmatched STRING columns come back empty ("").
| extend ReachedShell = isnotnull(FirstShell)
| extend ShellEvents  = coalesce(ShellEvents, 0)  // null would poison any later arithmetic
| summarize IPs = count(), NetworkEvents = sum(NetworkEvents) by ReachedShell
```

That last `summarize` gives you the real conversion rate: of everything the network layer saw,
what fraction ever reached a service. You cannot get that from an `inner` join, because `inner`
has already thrown the non-reaching IPs away.

**The null-versus-empty trap.** After a `leftouter`, an unmatched `long` or `datetime` column is
`null`, but an unmatched `string` column is the empty string `""`, not null. `isnull()` on a
string column returns `false` even when nothing matched. Use `isempty()` for strings and
`isnull()` for everything else — or sidestep it entirely by testing a non-string column, as
above.

---

## 🔎 leftanti — "in A but not B"

`kind=leftanti` keeps left rows that found **no** partner. It is the absence operator, and it is
the most useful join kind in threat hunting because most hunting questions are about absence:
what is new, what is missing, what got past something.

Two things about it that catch people:

- It returns **left columns only.** There are no right-side columns to project — there was no
  match. Trying to `project` one after a `leftanti` will not work.
- Because only the key is used, the right side should be reduced to `distinct` — anything more
  is wasted work.

**The headline question: which IPs hit the firewall but never reached the shell?**

```kusto
// Right side: every IP that the application layer saw at all. distinct = the key, nothing else.
let reachedShell =
    CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceVendor in ("sshd", "telnetd")
    | where isnotempty(SourceIP)
    | distinct SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor in ("Suricata", "nftables")
| where isnotempty(SourceIP)
| summarize NetworkEvents = count(),
            FirstSeen     = min(TimeGenerated),
            LastSeen      = max(TimeGenerated),
            PortsTouched  = dcount(DestinationPort),
            DeniedCount   = countif(DeviceAction == "Denied")
        by SourceIP
| join kind=leftanti reachedShell on SourceIP    // keep only IPs with NO application-layer row
| order by NetworkEvents desc
```

These are the scanners that never converted — knocked on the door, never opened it. Useful two
ways: as a block-list candidate population, and as a baseline. An IP that has been in this list
for days and then leaves it has just done something new.

**The other classic leftanti: what is new today?**

```kusto
// Baseline: IPs seen in the previous 7 days, ending 24h ago.
let baseline =
    CommonSecurityLog
    | where TimeGenerated between (ago(8d) .. ago(1d))
    | where isnotempty(SourceIP)
    | distinct SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where isnotempty(SourceIP)
| summarize Events = count(), Vendors = make_set(DeviceVendor) by SourceIP
| join kind=leftanti baseline on SourceIP        // first time we have ever seen this address
| order by Events desc
```

**Read every leftanti result twice.** `leftanti` proves "no matching row in the right-hand set as
I defined it" — which is not the same as "it did not happen." Three ways this workspace will lie
to you:

| The result says | It might actually mean |
|---|---|
| the IP never reached the shell | it did, but outside your right-side time window |
| this IP is brand new | your baseline window reached past 30-day retention and came back short |
| nothing happened on the endpoint | the sensor is down — see below |

That last one is live right now: **Sysmon on the Arc-connected laptop has been down since
2026-08-07.** Any `leftanti` that concludes "no endpoint activity for these IPs" is reporting a
sensor outage as an all-clear. Prove the sensor was alive before you trust an empty result:

```kusto
// Cheap, and worth running before any absence-based conclusion.
Heartbeat
| where TimeGenerated > ago(7d)
| summarize LastSeen = max(TimeGenerated), Beats = count() by Computer, Category
| order by LastSeen asc                          // anything stale floats to the top
```

---

## 🔎 fullouter — nobody gets dropped

`kind=fullouter` keeps everything from both sides. Its real use here is **sensor coverage
comparison**: which addresses did the IDS see, which did the firewall see, and which did only one
of them see?

```kusto
let ids =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "Suricata"
    | where isnotempty(SourceIP)
    | summarize IdsHits = count(), TopSignatures = make_set(Activity, 3) by SourceIP;
let firewall =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "nftables"
    | where isnotempty(SourceIP)
    | summarize FwHits = count(), Denied = countif(DeviceAction == "Denied") by SourceIP;
ids
| join kind=fullouter firewall on SourceIP
// fullouter keeps rows present on only one side, so the key arrives as TWO columns:
// SourceIP is empty on firewall-only rows, SourceIP1 is empty on IDS-only rows.
| extend SeenBy = case(isnotempty(SourceIP) and isnotempty(SourceIP1), "both sensors",
                       isnotempty(SourceIP),                           "IDS only",
                                                                       "firewall only")
| extend IP = coalesce(SourceIP, SourceIP1)      // coalesce skips empty strings too
| project IP, SeenBy, IdsHits, TopSignatures, FwHits, Denied
| order by SeenBy asc, IdsHits desc
```

**The split key column applies to `leftouter` too.** Writing `on SourceIP` returns both `SourceIP`
and `SourceIP1`. On a `leftouter` you can ignore `SourceIP1` because the left key is always
populated. On a `fullouter` you cannot — ignoring it means every firewall-only row appears to have
no IP address. The `coalesce` line above is not decoration.

Writing the key as `on $left.SourceIP == $right.SourceIP` gives the same two columns. If the
column names genuinely differ — say you are matching against a different field — the explicit form
is the only option:

```kusto
| join kind=leftouter someOtherSet on $left.SourceIP == $right.IndicatorAddress
```

---

## 🔎 union — when you just want rows stacked

A join asks "which rows relate to which?" and pays for key matching to answer it. **`union` just
stacks rows.** No key, no matching, no fan-out, no `kind=` to get wrong. If you only want one
combined list, `union` is both cheaper and impossible to get subtly wrong.

The single best use here is a **timeline for one attacker across every sensor**:

```kusto
let target = "203.0.113.10";                     // replace with an IP from your own results
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SourceIP == target
| project TimeGenerated,
          Sensor = DeviceVendor,
          Door   = DeviceEventCategory,          // empty for anything before 2026-08-22
          Event  = DeviceEventClassID,
          Action = DeviceAction,
          User   = DestinationUserName,
          Detail = Activity
| union (
    Syslog
    | where TimeGenerated > ago(24h)
    | where SyslogMessage has target             // raw text - substring match, not a column
    | project TimeGenerated,
              Sensor = "Syslog",
              Door   = "",
              Event  = ProcessName,
              Action = "",
              User   = "",
              Detail = SyslogMessage
  )
| order by TimeGenerated asc
```

Columns are matched by name; anything present on only one side comes back empty on the other. The
literal `Sensor = "Syslog"` is doing the job `union withsource=` does automatically — worth
knowing both, because the automatic version is shorter when you are unioning whole tables:

```kusto
// Which tables mention this address at all? A fast triage sweep before you commit to a hunt.
let target = "203.0.113.10";
union withsource = SourceTable
      CommonSecurityLog, Syslog, SecurityEvent
| where TimeGenerated > ago(24h)                 // narrow the window BEFORE the text search
| where * has target                             // full-text across every column of every table
| summarize Rows = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
        by SourceTable
```

That `where * has` is the heaviest thing in this document — it scans every column of three tables.
It is fine over 24 hours as a one-off triage sweep. Do not widen it to 30 days out of curiosity,
and never put it in a scheduled rule.

Two flags worth knowing:

| Flag | What it does |
|---|---|
| `union withsource = ColName` | adds a column naming which table each row came from |
| `union isfuzzy = true` | tolerates a table that does not exist instead of failing the query |

`isfuzzy=true` is genuinely useful across workspaces where a table may not be present — and
genuinely dangerous in a detection, because a typo'd table name silently contributes zero rows
instead of erroring.

---

## 🔎 Join or union? One question

**Do I need columns from both sources on the same row?**

- **Yes** → `join`. Now choose the `kind=` deliberately, and aggregate both sides to one row per
  key first.
- **No, I just want all the rows in one list** → `union`. Cheaper, and there is nothing to get
  wrong.

If you find yourself joining and then immediately `summarize`-ing away everything from one side,
you wanted `leftsemi` (matched left rows) or `leftanti` (unmatched left rows) — both return left
columns only and skip the fan-out entirely.

---

## 🔎 Cost and efficiency in this workspace

Be precise about what "cost" means here, because the honest answer is not the obvious one.

**Running a query does not add to the $15/month.** In a Log Analytics workspace on the Analytics
tier you are billed for **ingestion and retention**. An expensive join costs you time and
patience, not money. What it *can* cost:

| Constraint | Consequence |
|---|---|
| 10-minute query timeout | a heavy join fails to return at all |
| result-set caps (rows and size) | a fan-out join gets truncated — partial results, no warning |
| 30-day retention | any window past 30 days returns nothing, quietly |
| scheduled-rule runtime | a rule that times out stops detecting, and nobody gets an alert about that |

That last row is where efficiency actually protects you. There are 38 rules deployed, each one a
query on a schedule. A join that is slow interactively is a detection that misses its window in
production. **The expensive failure mode is a missed detection, not a bigger bill.**

Money does enter in two places worth flagging: data queried from long-term retention or
lower-cost log tiers is charged per scan rather than being free, and re-ingesting query output
(summary rules, exports) is charged as new ingestion. Neither is what the queries in this
document do, but both are one design decision away.

**Five habits, in the order they pay off:**

1. **Filter time on both sides, inside each `let`.** A time filter on the final pipeline does not
   reach backwards into the right-hand operand.
2. **Reduce before joining.** `summarize` / `distinct` / `project` down to the key plus what you
   actually need. This is the same habit that fixes correctness — it is not a separate discipline.
3. **Smaller table on the left.** Documented Kusto guidance, and it matters more as both sides
   grow.
4. **Prefer `union` when you do not need key matching.** No shuffle, no matching, no fan-out.
5. **If a join is still slow**, `hint.shufflekey = SourceIP` helps when the key is
   high-cardinality and both sides are large; `hint.strategy = broadcast` helps when the left side
   is genuinely tiny. Reach for hints only after 1–4, because 1–4 usually make them unnecessary.

```kusto
// The shape of an efficient join: both sides scoped, both sides reduced, kind= explicit.
let recentShell =
    CommonSecurityLog
    | where TimeGenerated > ago(1h)              // scoped INSIDE the let, not after the join
    | where DeviceVendor == "sshd"
    | distinct SourceIP;                         // reduced to the key alone
CommonSecurityLog
| where TimeGenerated > ago(1h)                  // and scoped on this side too
| where DeviceVendor == "Suricata"
| summarize Alerts = count() by SourceIP
| join kind=inner recentShell on SourceIP        // kind= always written out
```

---

## 🔎 Gotchas that produce wrong answers silently

Every item here returns a table. None of them throws an error.

| # | Gotcha | What it does to you | Fix |
|---|---|---|---|
| 1 | no `kind=` | silent `innerunique`; left side deduped, counts understated | always write `kind=` |
| 2 | unaggregated `kind=inner` | row counts are a product, not a population | aggregate both sides by the key first |
| 3 | mismatched time windows across `let`s | one side sees a narrower population; `leftanti` calls things "new" that are not | put the same `ago()` in every `let` — or bind one `let lookback = 24h;` |
| 4 | `isnull()` on a string after `leftouter` | always false; unmatched strings are `""`, not null | `isempty()` for strings, `isnull()` for the rest |
| 5 | ignoring `SourceIP1` after `fullouter` | right-only rows appear to have no key | `coalesce(SourceIP, SourceIP1)` |
| 6 | projecting a right column after `leftanti` | there are no right columns — nothing matched | carry what you need on the left side |
| 7 | comparing `LogSeverity` directly | it is a **string**; `"10" < "9"` as text, so severity 10 is excluded | `toint(LogSeverity)` before comparing |
| 8 | joining on `DeviceEventCategory` | populated only from 2026-08-22 — older rows silently excluded | join on `DeviceVendor` for anything historical |
| 9 | `leftanti` against a dead sensor | absence of telemetry read as absence of activity | check `Heartbeat` first (Sysmon: down since 2026-08-07) |
| 10 | window wider than 30 days | returns nothing from beyond retention, no warning | keep joins inside 30 days |

Number 7 in context — this is a real correctness bug, not a style note:

```kusto
let highSevIds =
    CommonSecurityLog
    | where TimeGenerated > ago(24h)
    | where DeviceVendor == "Suricata"
    | extend Severity = toint(LogSeverity)       // LogSeverity is a STRING in this table.
                                                 // Without toint(), >= "8" drops "10" because
                                                 // "10" sorts before "9" as text.
    | where Severity >= 8
    | summarize IdsAlerts = count(), Signatures = make_set(Activity, 5) by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.success"
| summarize Logins = count(), UsersUsed = make_set(DestinationUserName, 5) by SourceIP
| join kind=inner highSevIds on SourceIP         // high-severity IDS hit AND a successful login
| project SourceIP, Logins, UsersUsed, IdsAlerts, Signatures
| order by IdsAlerts desc
```

Both sides are one row per `SourceIP`, both are time-scoped, `kind=` is explicit, and the string
column is converted before comparison. That is the whole checklist in one query.

---

## 🔎 Practice

Work these in order. Each one is a question first — write the query yourself before scrolling back
to the pattern that fits.

| # | Question | Kind you should land on |
|--:|---|---|
| 1 | Which IPs did both the network layer and the shell see in the last 24h? | `inner`, both sides aggregated |
| 2 | Of all IPs the firewall saw this week, what share ever reached the shell? | `leftouter` — the denominator matters |
| 3 | Which IPs hit the firewall but never reached the shell? | `leftanti` |
| 4 | Which IPs appeared today that were absent the previous week? | `leftanti` against a baseline |
| 5 | Which IPs did Suricata see that nftables did not, and vice versa? | `fullouter` with `coalesce` |
| 6 | Build a full timeline for one attacker across every sensor. | `union`, not a join |
| 7 | Take query 1 and delete the `kind=`. Explain the number change. | back to the top of this page |

Then take the one you find most useful, check it against the deployed
[detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md),
and see whether one of the 38 rules already covers it — and if it does, whether it wrote the join
the same way you did.

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [`summarize/`](../summarize/) &nbsp;·&nbsp; [`performance/`](../performance/) &nbsp;·&nbsp; [`threat-hunting/`](../threat-hunting/)
