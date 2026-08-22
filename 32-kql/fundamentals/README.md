# KQL Fundamentals — how to get from reading queries to writing them

**Module:** 32 — KQL &nbsp;·&nbsp; **Area:** `fundamentals/`
**Workspace:** `la-lab-eus-01` (Microsoft Sentinel → Logs)
**Time:** ~30 minutes for the first session
**Who this is for:** you can read a KQL query and follow what it does, but a blank query window still beats you.

That gap is smaller than it feels. It is not a vocabulary problem — you do not need more operators. It is a
**structure** problem: you have not yet internalised that every query is the same shape, and that you build it
one line at a time instead of composing it in your head.

Everything below runs against this lab's own data. The honeypot is internet-facing and takes real attacker
traffic continuously, so `CommonSecurityLog` is never empty and you are never practising on toy rows.

---

## 🔎 The pipeline is the entire language

A KQL query is a **table**, then a series of **operators**, joined by pipes:

```
Table | operator | operator | operator
```

Data flows strictly left to right. Each stage takes a table in and emits a table out. That is the whole
mental model, and it has two consequences that matter more than any syntax you will memorise:

| Consequence | What it means in practice |
|---|---|
| **Order is meaningful** | `where` then `summarize` is not the same query as `summarize` then `where`. The first filters raw rows; the second filters the aggregated result. |
| **Each stage only sees the previous one** | If you `project` a column away, no later line can reference it. Most "unknown column" errors are this. |

So every stage does one of two jobs — **narrow** (fewer rows: `where`, `take`) or **reshape** (different
columns: `project`, `extend`, `summarize`). Ask which one you need next, and you have picked your operator.

Read this query as four separate steps rather than one sentence:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)          // narrow: 24 hours only
| where DeviceVendor == "sshd"            // narrow: the fake SSH shell
| where DeviceEventClassID == "login.failed"  // narrow: failed logins only
| project TimeGenerated, SourceIP, DestinationUserName, DeviceCustomString2  // reshape
| take 20
```

**The habit to build:** write line 1, run it. Add line 2, run it. Add line 3, run it. You will feel slow for
about a week and then you will be faster than people who type the whole thing and debug it backwards. There
is no prize for composing a query in one go, and a query that grew line by line is one you actually
understand.

---

## 🔎 Always filter on TimeGenerated first — and why

This is the one rule to follow before you understand the reason for it.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)   // ← this line comes first, every time
| where SourceIP == "<paste an IP from your own results>"
```

Not this:

```kusto
CommonSecurityLog
| where SourceIP == "<paste an IP from your own results>"
| where TimeGenerated > ago(24h)   // ← works, but you have already asked for everything
```

Four reasons, in the order they will bite you:

1. **Log Analytics partitions data by time.** A leading `TimeGenerated` filter lets the engine skip whole
   chunks of storage instead of reading and discarding them. Every other filter is applied to whatever
   survives this one, so this is the only filter that changes how much data is *touched*.
2. **This workspace keeps 30 days.** `ago(90d)` does not error — it returns whatever exists, which is at most
   30 days of it. If you write `ago(90d)` and get less than you expected, the query is fine and your
   assumption was wrong. Do not go hunting for a broken pipeline.
3. **The honeypot never stops.** It takes continuous internet traffic, so an unbounded `CommonSecurityLog`
   is genuinely large. On the Entra or `AzureActivity` tables you can get away with sloppiness. Here you
   cannot, and here is where you should be practising.
4. **You are training the muscle for scheduled rules.** Every one of this lab's **38 analytics rules** is a
   KQL query running on a timer — see the [detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md).
   A rule with a sloppy lookback runs sloppily every few minutes, forever.

**On cost, stated accurately:** running an interactive query in the Logs blade against a normal
(Analytics-tier) table is *not* billed per query — the **$15/month** budget goes on ingestion and retention,
not on you pressing Run. So exploring is free, and you should explore a lot. What genuinely costs money is
ingesting more data, retaining it longer, and search jobs or archive restores that reach past retention —
those *are* billed by the volume they scan. Build the discipline now on free queries so that it is already a
habit when you are writing something that runs on a schedule or reaches into archived data.

---

## 🔎 The six operators that cover about 90% of real work

Learn these six properly and stop. Everything else — `join`, `parse`, `mv-expand`, `bin`, `make-series` — is
worth learning *after* these are automatic, and most shifts never need them.

| Operator | Job | Narrow or reshape |
|---|---|---|
| `where` | Keep rows matching a condition | Narrow |
| `project` | Choose which columns to keep, and their order | Reshape |
| `extend` | Add a new calculated column | Reshape |
| `summarize` | Collapse many rows into aggregates, grouped by something | Reshape |
| `order by` | Sort the result | Neither — presentation |
| `take` | Return N arbitrary rows | Narrow |

### `where` — the one you will type most

Conditions stack. Two `where` lines and one `where ... and ...` are equivalent, and separate lines are easier
to comment out while debugging, which is why the house style prefers them.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "nftables"        // the host firewall
| where DeviceAction == "Denied"          // Allowed | Denied
| take 20
```

String comparison gotcha worth knowing on day one: `==` is case-sensitive and fast, `=~` is case-insensitive
and slower. `contains` searches anywhere in the string and is slower again. Prefer `==` when you know the
exact value — and after the exploration step below, you will know the exact value.

### `project` — decide what you are looking at

`CommonSecurityLog` is a wide CEF table. Most of its columns are empty in this lab because CEF defines far
more fields than these sensors emit. `project` is how you stop scrolling sideways.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Suricata"        // the inline IDS/IPS
| project TimeGenerated, SourceIP, DestinationPort, Activity, DeviceCustomString1
// Activity = the Suricata signature name; DeviceCustomString1 = priority
```

Two relatives worth knowing now: `project-away` drops named columns and keeps the rest, and `project-rename`
renames without dropping. Use `project-away` when you want almost everything.

### `extend` — add a column that did not exist

The single most useful `extend` in this workspace, because it fixes a real trap:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| extend Severity = toint(LogSeverity)   // LogSeverity is a STRING here, not a number
| where Severity >= 7
| project TimeGenerated, SourceIP, Activity, Severity
| order by Severity desc
```

**Why `toint()` is not optional.** `LogSeverity` arrives as CEF text, so it is a string column. Comparing
strings compares them alphabetically, and alphabetically `"10" < "9"` — because `1` sorts before `9`. A
severity filter written without `toint()` silently drops your highest-severity events. It does not error. It
just quietly gives you the wrong answer, which is the worst kind of bug in detection work.

The general lesson: **`extend` is where you normalise before you compare.** Cast the type, do the arithmetic,
build the label — then filter on the clean column.

### `summarize` — where reading turns into analysing

Everything so far shows you rows. `summarize` is what answers questions. It has two halves: the aggregations
you want, and the `by` clause you want them grouped by.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize
    Attempts     = count(),
    UsersTried   = dcount(DestinationUserName),   // dcount = distinct count
    PasswordsTried = dcount(DeviceCustomString2), // sshd puts the attempted password here
    FirstSeen    = min(TimeGenerated),
    LastSeen     = max(TimeGenerated)
    by SourceIP
| order by Attempts desc
| take 20
```

That is a real brute-force triage query, and it is five operators you already know. The four aggregations you
will use constantly: `count()`, `dcount()`, `min()`, `max()`. Add `make_set()` when you want to see the actual
distinct values rather than just how many there were.

**The rule that catches everyone:** after `summarize`, only the columns you created and the columns in the
`by` clause still exist. Adding `| project SourcePort` after the query above fails, because `summarize` threw
that column away. This is the pipeline model doing exactly what it says.

### `order by` and `take` — always together, always last

`order by` (its alias `sort by` is identical) puts the interesting rows on top. `take` limits the output.

The distinction to get right: **`take` returns arbitrary rows, not the first or the best ones.** Two runs of
the same `take 10` can return different rows. That makes it perfect for sampling and wrong for "top 10" — for
a real top 10, sort first, or use `top 10 by Attempts desc`, which does both in one operator.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| summarize Attempts = count() by SourceIP
| top 10 by Attempts desc   // sort + limit in one; honest "top N"
```

---

## 🔎 How to explore a table you have never seen

You will meet unfamiliar tables constantly. There is a fixed three-step recipe, and it takes about ninety
seconds. Do not skip to writing a detection before you have run it.

### Step 1 — `take 10`: what does a row even look like?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| take 10
```

You are not analysing here. You are answering: is there data at all, how wide is this table, and which
columns are actually populated versus defined-but-empty. Scroll sideways and look.

### Step 2 — `getschema`: what are the columns and their types?

```kusto
CommonSecurityLog
| getschema
```

This returns the column list and data types, not rows, so it is cheap and needs no time filter. Use it the
moment a comparison behaves strangely — it is how you discover that `LogSeverity` is a `string`, before it
costs you an hour.

### Step 3 — `distinct` on the interesting column: what values exist?

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| distinct DeviceVendor
```

This is the step that turns guessing into knowing. You now have the exact strings to use with `==` instead of
reaching for `contains` and hoping.

In practice, upgrade `distinct` to a counted `summarize` almost immediately — same information, plus the shape
of the data, for the same effort:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count(), Last = max(TimeGenerated)
    by DeviceVendor, DeviceEventClassID
| order by Events desc
```

**One caution on `distinct`:** on a high-cardinality column such as `SourceIP` over a long lookback it has to
hold every unique value, which is slow and rarely what you wanted. `summarize count() by SourceIP | top 20`
is almost always the better question anyway.

---

## 🔎 What this lab actually puts in `CommonSecurityLog`

CEF is a generic format, so the column *names* tell you nothing about what this lab means by them. This
mapping is the difference between guessing and working. Everything here is on `Computer` =
`db-finance-prod01`.

| Column | What it holds here |
|---|---|
| `DeviceVendor` | Which sensor: `sshd` / `telnetd` (the fake shell), `Suricata` (inline IDS/IPS), `nftables` (host firewall) |
| `DeviceEventClassID` | sshd: `session.connect`, `login.failed`, `login.success`, `command.input`, `session.file_download`, `session.file_upload` · Suricata: `gid:signature_id`, e.g. `1:2024897` · nftables: `ALLOW-SVC`, `DENY-SENSITIVE` |
| `DeviceEventCategory` | The sensor's position in the traffic path: `Door 2 - Host Firewall`, `Door 3 - Network IDS/IPS - <cat>`, `Door 4 - Application Shell (SSH)` |
| `DeviceAction` | `Allowed` or `Denied` |
| `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `Protocol` | Standard network five-tuple |
| `DestinationUserName` | The username the attacker tried |
| `DeviceCustomString1` | sshd: session id · Suricata: priority · nftables: interface |
| `DeviceCustomString2` | sshd: **the password tried** |
| `DeviceCustomString3` | sshd: **the command typed** |
| `Activity` | Human-readable event name, or the Suricata signature name |
| `LogSeverity` | CEF severity, as a **string** — `toint()` it before comparing |

Three things to know before they confuse you:

- **The custom string columns are overloaded.** `DeviceCustomString1` means something different per vendor.
  Always pair a `DeviceCustomString*` filter with a `DeviceVendor` filter, or you are comparing session ids
  against firewall interface names.
- **`DeviceEventCategory` was added on 2026-08-22.** Records ingested before that will not have it populated,
  so a query filtering on it over a long lookback will return far less than you expect. That is the column
  being new, not the query being broken. Prefer `DeviceVendor` for anything historical.
- **The `DeviceEventClassID` list above is the sshd set.** Do not assume `telnetd` emits exactly the same
  values — run the counted `summarize` from Step 3 and find out. That is precisely the habit this section is
  trying to build.

**A note on the other tables while you are here.** `Syslog` is the same host in raw text — keep it for
investigation, not detection, because unstructured text is painful to write reliable rules against.
`SecurityEvent` carries Windows events from an Arc-connected laptop, but **Sysmon on it has been down since
2026-08-07**, so a thin result there is a broken sensor rather than a quiet one. Learn on `CommonSecurityLog`
first; it is the richest table in this workspace by a distance.

---

## 🔎 Your first 30 minutes, concretely

Open **Microsoft Sentinel → Logs** on `la-lab-eus-01` and work through these six blocks in order. Type every
query rather than pasting it — the point is the typing. Run each line before adding the next.

### Minutes 0–5 · Prove there is data and see a row

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| take 10
```

Then delete the `take 10` and replace it with `| count` to see how many events one hour produced. Real
attacker traffic; that number is genuinely arriving.

### Minutes 5–10 · Learn the schema, find the trap

```kusto
CommonSecurityLog
| getschema
```

Find `LogSeverity` in the output and confirm for yourself that it is a `string`. This is the fact that will
save you an hour later.

### Minutes 10–15 · Map the sensors

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events = count(), Last = max(TimeGenerated)
    by DeviceVendor, DeviceEventClassID
| order by Events desc
```

You now know which sensors are live, what each one emits, and roughly in what proportion. Keep this result
open — the next three blocks are just filtered views of it.

### Minutes 15–20 · Ask your first real question

*Who is brute-forcing the fake SSH service, and how hard?*

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize
    Attempts   = count(),
    UsersTried = dcount(DestinationUserName),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated)
    by SourceIP
| order by Attempts desc
| take 20
```

Build it one line at a time. Notice the row count fall as each `where` lands — that is the pipeline narrowing,
and watching it happen is the point of the exercise.

### Minutes 20–25 · Look at the credentials themselves

*What usernames and passwords are actually being tried?*

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.failed"
| summarize Attempts = count()
    by DestinationUserName, Password = DeviceCustomString2  // rename inline in the by clause
| order by Attempts desc
| take 25
```

Two things to take from this: you can rename a column inside the `by` clause, and `summarize ... by A, B`
groups by the *combination*, which is why you get credential pairs rather than two separate lists.

### Minutes 25–30 · Follow an attacker past the login

*What did they type once they were in?*

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "command.input"
| project TimeGenerated, SourceIP, Session = DeviceCustomString1, Command = DeviceCustomString3
| order by TimeGenerated asc   // ascending, so the session reads as a story
| take 50
```

This is the payoff, and it is worth sitting with. Every operator here you learned in the last twenty-five
minutes, and the output is an attacker's actual keystrokes on an internet-facing host. Pick one `Session`
value, add `| where DeviceCustomString1 == "<that session>"`, and read that one intrusion start to finish.

**If you want one more:** find sessions that got in at all.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "login.success"
| project TimeGenerated, SourceIP, DestinationUserName,
          Password = DeviceCustomString2, Session = DeviceCustomString1
| order by TimeGenerated desc
```

Correlating those sessions back to their commands is a `join`, which is the next area to learn — but note that
you can get a long way by just reading the session id off one result and filtering the other by hand. Do that
a few times before reaching for `join`; you will understand what `join` is doing when you get there.

---

## 🔎 Habits that separate people who write KQL from people who paste it

| Habit | Why it pays |
|---|---|
| Build line by line, running each time | You never debug more than one line at a time |
| `TimeGenerated` filter always first | Correctness, speed, and the habit that scheduled rules need |
| `getschema` before you trust a comparison | Catches string-typed numbers like `LogSeverity` |
| `summarize count() by X` instead of scrolling | Turns an unreadable row dump into an answer you can read |
| `distinct` first, `==` after | Stops you reaching for `contains` out of uncertainty |
| Comment the non-obvious line with `//` | You will reread this query in three weeks with no memory of it |
| Name your aggregations (`Attempts = count()`) | `count_` as a column name helps nobody |

---

## 🔎 You know enough when you can…

Not "when you have read this" — when you can do each of these from a blank query window, without looking
anything up:

- [ ] Explain what a `|` does, and why moving one line changes the answer
- [ ] Write a `TimeGenerated` filter as the first line without thinking about it
- [ ] Run the three-step recipe (`take 10` → `getschema` → `distinct`) on a table you have never opened
- [ ] Name the six core operators and say whether each narrows or reshapes
- [ ] Write a `summarize ... by ...` with two aggregations and a two-column `by` clause
- [ ] Say why `| project SourcePort` fails after a `summarize` that did not include it
- [ ] Explain why `toint(LogSeverity)` matters, and what breaks silently without it
- [ ] Say why `take 10` is not "the first 10 rows", and use `top ... by ...` when you need a real top N
- [ ] Find the top 10 brute-force source IPs in the last 24 hours in under two minutes
- [ ] Read one attacker session's commands end to end using only `where`, `project`, `order by`

When all ten are true, stop drilling fundamentals. Go to `operators/` and `summarize/` for depth, then
`joins/` — and read the [detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
to see what these six operators look like when they are doing production work across 38 rules.

---

[← Module 32 — KQL](../README.md) &nbsp;·&nbsp; [Roadmap](../../README.md)
