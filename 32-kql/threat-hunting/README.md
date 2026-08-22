# Threat hunting with KQL

![Area](https://img.shields.io/badge/Area-threat--hunting-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)
![Retention](https://img.shields.io/badge/Retention-30%20days-0078D4?style=flat-square)
![Hunts](https://img.shields.io/badge/Hunts-8-0078D4?style=flat-square)

Writing KQL that goes looking for things, rather than KQL that waits for things.

> **These queries target this lab's real workspace.** Every table and column used below comes from
> the schema this environment actually populates — see [What this workspace actually
> holds](#-what-this-workspace-actually-holds). Nothing here is presented as already executed. Run
> them yourself, and record what came back.

**Where this sits in the lab.** The systematic, MITRE-mapped version of this work lives in the
lab's own hunt program:
[`THREAT-HUNTING-LIBRARY/`](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/THREAT-HUNTING-LIBRARY/README.md).
That repo organises hunts by tactic → technique and writes up each result with evidence. **This
page is the technique training** — how the queries are built and why they are shaped the way they
are. Learn the shapes here, then contribute hunts there.

---

## 🔎 Hunting is not alerting

A detection encodes an answer in advance. A hunt asks a question that nobody has encoded yet.

| | Detection (analytics rule) | Hunt |
|---|---|---|
| **Starts from** | a known-bad pattern | a hypothesis you wrote down |
| **Threshold** | required — it decides when to fire | none, deliberately |
| **Schedule** | runs unattended, forever | you run it, once, on purpose |
| **Output** | an incident in a queue | a conclusion, written down |
| **Who looks** | the rule looks; a human reads the result | **you look** |
| **Empty result** | means nothing happened | is a finding — it narrows the space |
| **In this lab** | [38 deployed rules](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md) | [the hunt program](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/THREAT-HUNTING-LIBRARY/README.md) |

The single most useful line in that table is the threshold row. A rule needs a number, and choosing
that number is what makes rules miss things: "more than 8 failures in 10 minutes" cannot see the
attacker who does 7. A hunt has no number, so it can see the whole distribution — which is exactly
why the interesting hunting techniques below are all about **looking at shape, not volume**.

Three things worth being honest about before you start:

**Most hunts find nothing.** That is the normal outcome, not a failure. A well-designed hunt that
returns zero rows has told you something real.

**A hunt you cannot repeat is worth very little.** Write down the query, the window, and the date.
Next month's run is only meaningful as a comparison.

**You cannot hunt what you never ingested.** A hunt over a table with no data returns zero rows for
a reason that has nothing to do with the adversary. [Hunt 8](#hunt-8--the-hunt-that-validates-the-other-seven)
exists entirely because of this.

---

## 🗄️ What this workspace actually holds

Hunting starts with knowing your own surface. This is what `la-lab-eus-01` has, and what each
source is good for.

| Table | What's in it | Good for hunting? |
|---|---|---|
| `CommonSecurityLog` | The honeypot's CEF feed — SSH shell, Suricata IDS/IPS, nftables firewall | **Yes — the richest table here.** Most hunts below live in it |
| `Syslog` | Same host, raw unparsed text | Investigation, not detection — no reliable fields to pivot on |
| `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs` | Entra ID sign-ins and directory audit | Yes — and the only place a *real* identity compromise would show |
| `AzureActivity` | Subscription control plane operations | Yes — resource-level attacker behaviour |
| `SecurityEvent` | Windows events from an Arc-connected laptop | Partly — **Sysmon on it has been down since 2026-08-07** |
| `StorageBlobLogs` | Blob read / write / delete | Yes, for data-access hunts |
| `AppServiceHTTPLogs` | The public decoy website | Yes — pairs well with the honeypot for cross-surface pivots |
| `Heartbeat`, `Usage` | Agent health, ingestion volume | Yes — for hunting your own blind spots and your bill |

### The `CommonSecurityLog` schema as this lab populates it

Generic CEF documentation will not tell you what these custom fields mean **here**. This mapping is
the difference between a hunt that runs and a hunt that invents columns.

| Field | What this lab puts in it |
|---|---|
| `DeviceVendor` | `sshd` or `telnetd` (the fake shell — deliberately not named after the honeypot software), `Suricata` (inline IDS/IPS), `nftables` (host firewall) |
| `DeviceEventClassID` | **sshd:** `session.connect`, `login.failed`, `login.success`, `command.input`, `session.file_download`, `session.file_upload` · **Suricata:** `gid:signature_id`, e.g. `1:2024897` · **nftables:** `ALLOW-SVC`, `DENY-SENSITIVE` |
| `DeviceEventCategory` | The sensor's position in the traffic path — `Door 2 - Host Firewall`, `Door 3 - Network IDS/IPS - <cat>`, `Door 4 - Application Shell (SSH)`. **Added 2026-08-22** |
| `DeviceAction` | `Allowed` or `Denied` |
| `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `Protocol` | Standard connection tuple |
| `DestinationUserName` | The username the attacker tried |
| `DeviceCustomString1` | **sshd:** session id · **Suricata:** priority · **nftables:** interface |
| `DeviceCustomString2` | **sshd:** the password tried |
| `DeviceCustomString3` | **sshd:** the command typed |
| `Activity` | Human-readable event name, or the Suricata signature name |
| `LogSeverity` | CEF severity **as a string** — `toint()` it before comparing |
| `Computer` | `db-finance-prod01` |

Two traps live in that table:

**`LogSeverity` is a string.** `where LogSeverity > 5` does a *lexical* comparison, so `"10"` sorts
below `"5"` and your high-severity hunt silently drops its highest-severity rows. Always
`toint(LogSeverity)` first.

**`DeviceEventCategory` only exists on data ingested from 2026-08-22.** Any hunt using it has an
effective start date, no matter what you put in `ago()`. Rows older than that carry an empty value
and fall out of an `isnotempty()` filter — which is the honest behaviour, but you should know it is
happening rather than reading a short result as a quiet week.

---

## 🧠 Forming a hypothesis

A hypothesis is not a topic. "Look for weird SSH activity" is a topic, and it produces a query you
cannot evaluate — because no result would confirm or deny anything.

A usable hypothesis names four things:

| Part | Example |
|---|---|
| **The actor's goal** | An attacker who got a shell wants to know what box they landed on |
| **The behaviour it forces** | They will run reconnaissance commands — `whoami`, `uname -a`, `cat /etc/passwd` |
| **Where that lands in telemetry** | `CommonSecurityLog`, `DeviceVendor == "sshd"`, `DeviceEventClassID == "command.input"`, command text in `DeviceCustomString3` |
| **What a negative result means** | Either nobody got that far, or they used a technique that does not type commands |

Write it as one sentence before you write any KQL:

> *If an attacker got past the fake shell's login, they would orient themselves before doing
> anything else. I expect reconnaissance commands in `DeviceCustomString3` within minutes of a
> `login.success` in the same session.*

That sentence tells you the table, the filter, the join key, and how to interpret an empty result.
A hypothesis that does not survive being written down is one you were never going to be able to
evaluate anyway.

**The honeypot makes hypotheses cheap.** `db-finance-prod01` is internet-facing and takes real
attacker traffic continuously, and it has no legitimate users. That is an unusually clean place to
hunt: on a production box you spend most of your effort separating attackers from employees, and
here every row is already hostile or already yours. Hypotheses about *attacker behaviour* — how
they orient, what they try first, what they bring with them — can be tested here directly.

---

## 📊 Stack counting

The technique that finds things no threshold ever will.

**The idea.** Take a field an attacker has to populate to do their job. Count how often each
distinct value appears. Sort **ascending**. Read the bottom of the list.

**Why the bottom.** Volume-based detection looks at the top: the loudest IP, the most-attempted
username. But the top of the list is commodity — mass scanners, shared wordlists, the same botnet
software everybody else on the internet is also seeing. It is the *rare* value that carries
information. A command typed once, by one source, in one session, is either a mistake or a
decision, and both are more interesting than the ten thousandth `root/123456` attempt.

The generic shape:

```kusto
<Table>
| where TimeGenerated > ago(14d)
| where <narrow to one behaviour>            // stack one thing, not everything
| summarize Times = count(),
            Sources = dcount(SourceIP)        // "how many people do this" beats "how often"
        by <the rare thing>
| order by Times asc                          // ASCENDING - the hunt is at the bottom
| take 40                                     // cap it; a hunt returning 10k rows is a new problem
```

Two refinements that make it much sharper:

**Count distinct sources, not just events.** A value used a thousand times by one IP is a loop. A
value used once each by a thousand IPs is a shared toolkit. `dcount(SourceIP)` separates them and
`count()` alone cannot.

**Stack one behaviour at a time.** Stacking every event class together mixes populations, and the
rare values you surface will be rare only because they belong to a small event type. Filter to one
`DeviceEventClassID` first.

---

## 📐 Baseline, then diff

Stack counting finds what is rare. Baselining finds what is **new** — which is often the same
insight arrived at from the other side.

**The idea.** Summarise what normal looked like over a long window. Summarise the recent window
separately. Keep only the recent things absent from the baseline. `leftanti` is the operator that
does it — "in the right-hand set, not in the left" — and it is the workhorse of behavioural
hunting.

```kusto
let baseline = <Table>
| where TimeGenerated between (ago(28d) .. ago(2d))   // MUST NOT overlap the test window
| summarize by <key>;
<Table>
| where TimeGenerated > ago(2d)
| join kind=leftanti baseline on <key>                 // things with no history
```

**The mistake that looks like a clean environment.** If the baseline window includes the period you
are testing, every recent value is already "known" and the hunt returns nothing. `ago(28d)` as a
baseline against `ago(2d)` as a test is wrong; `between (ago(28d) .. ago(2d))` is right. An empty
result from an overlapping baseline is indistinguishable from an empty result from a quiet
environment, which is what makes this error expensive.

**Retention constrains the arithmetic here.** This workspace keeps 30 days by default, so the
baseline and the test window together must fit inside 30 days — and a baseline that runs right up
against the retention edge is quietly shrinking every day as the oldest rows age out. A 28-day
baseline plus a 2-day test uses the space honestly. The 30-day ceiling also means **you cannot
baseline seasonality**: month-over-month or "same week last quarter" comparisons are not available
in this workspace, and pretending otherwise produces confident nonsense. If a hunt needs a longer
memory, it needs a summary rule writing daily aggregates to a custom table first — that is a
different piece of work, not a longer `ago()`.

---

## 💰 What a hunt costs

The budget for this lab is **$15/month**, which is low enough that query habits matter.

Running a query in **Logs** does not cost ingestion — you already paid to ingest the data. What
hunting can cost you is **archive/search jobs** if you reach past retention, and the real risk is
less about money than about time: an unfiltered `union *` across a workspace is slow, times out,
and teaches you nothing while it does.

Three habits that keep hunts cheap and fast:

| Habit | Why |
|---|---|
| **Filter on `TimeGenerated` first, always** | It is the partition key. Every other filter runs on a smaller set afterwards |
| **Name your tables in a `union`** | `union *` touches everything, including the tables you know are irrelevant |
| **`summarize` before you `join`** | Joining raw rows to raw rows multiplies work; joining two small summarised sets does not |

Know what you are paying for before you tune anything:

```kusto
// Where the ingestion budget actually goes, by table
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize GB = round(sum(Quantity) / 1024, 2) by DataType   // Quantity is in MB
| order by GB desc
```

Two hunts below are flagged as expensive. Both are worth running — just not on a loop.

---

## 🎯 The hunts

Eight hunts against this workspace. Each states its hypothesis first, because the hypothesis is the
part that transfers and the KQL is the part that does not.

---

### Hunt 1 — What did attackers type that nobody else typed

> **Hypothesis:** Automated SSH bots run a short, identical command list because they are all
> running the same tooling. A human — or a toolkit nobody else is using yet — types something the
> crowd does not. If I stack every command typed in the fake shell and read the *bottom* of the
> list, the unusual operators surface without me having to guess what "unusual" looks like.

This is the canonical stack count, and the best first hunt in this environment because the honeypot
guarantees the table is populated.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor == "sshd"
| where DeviceEventClassID == "command.input"    // stack ONE behaviour, not the whole feed
| where isnotempty(DeviceCustomString3)          // DeviceCustomString3 = the command typed
| summarize Times = count(),
            Sessions = dcount(DeviceCustomString1),   // DeviceCustomString1 = session id
            Sources = dcount(SourceIP),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
        by Command = DeviceCustomString3
| order by Times asc                             // ascending on purpose - rarest first
| take 40
```

**How to read it.** A command with `Times == 1` and `Sources == 1` is the highest-value row on the
page. Rows where `Sessions` is much lower than `Times` are loops inside one session. Anything
referencing an external host, a package manager, or a path outside `/tmp` deserves a second query
of its own.

**Flip it once.** Change `asc` to `desc` and look at the top for one minute. That is what the
commodity baseline looks like, and seeing it makes the bottom of the list mean more.

---

### Hunt 2 — Usernames with no history

> **Hypothesis:** Credential-stuffing tools cycle the same public username lists, so the set of
> usernames attempted against this host should be stable over weeks. A username that appears in the
> last two days and never appeared in the preceding four weeks suggests either a new wordlist in
> circulation or someone who has learned something specific about this host — for example an
> account name only visible if they got further in than the login prompt.

The baseline-then-diff shape, with the window arithmetic sized to fit 30-day retention.

```kusto
let TestWindow = 2d;
let BaselineStart = 28d;
let BaselineEnd = 2d;                            // baseline ENDS where the test window BEGINS
let baseline = CommonSecurityLog
| where TimeGenerated between (ago(BaselineStart) .. ago(BaselineEnd))
| where DeviceVendor == "sshd"
| where DeviceEventClassID in ("login.failed", "login.success")
| summarize by DestinationUserName;              // just the key - keep the baseline small
CommonSecurityLog
| where TimeGenerated > ago(TestWindow)
| where DeviceVendor == "sshd"
| where DeviceEventClassID in ("login.failed", "login.success")
| join kind=leftanti baseline on DestinationUserName   // usernames absent from 4 weeks of history
| summarize Attempts = count(),
            Sources = dcount(SourceIP),
            Succeeded = countif(DeviceEventClassID == "login.success"),
            FirstSeen = min(TimeGenerated)
        by DestinationUserName
| order by Succeeded desc, Attempts desc
```

**How to read it.** `Sources == 1` with a handful of attempts is targeted; dozens of sources
arriving with the same new username on the same day is a wordlist that just got published. Any row
where `Succeeded > 0` goes to the top of your list regardless of volume.

**Check before you trust an empty result.** If this returns nothing, confirm the baseline window
actually holds data before concluding the username set is stable — retention may have eaten the far
end of it.

---

### Hunt 3 — Passwords only one source ever tried

> **Hypothesis:** Public breach wordlists are shared, so almost every password attempted against an
> internet-facing host will be attempted by many unrelated IPs. A password tried by exactly one
> source is not from the common pool — it is a typo, a targeted guess, or knowledge of this
> environment specifically. That third case is the one worth finding.

Stack counting applied to credentials, using `dcount` as the filter rather than volume.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor == "sshd"
| where DeviceEventClassID in ("login.failed", "login.success")
| where isnotempty(DeviceCustomString2)          // DeviceCustomString2 = the password tried
| summarize Sources = dcount(SourceIP),
            Attempts = count(),
            Succeeded = countif(DeviceEventClassID == "login.success"),
            Usernames = make_set(DestinationUserName, 10),
            LastSeen = max(TimeGenerated)
        by Password = DeviceCustomString2
| where Sources == 1                             // one IP and only one - outside the shared pool
| order by Succeeded desc, Attempts desc
| take 40
```

**How to read it.** Most rows will be junk — mangled strings, encoding artefacts, half-sent
packets. You are reading for a password that looks *considered*: something containing the hostname,
the word finance, a year, or a plausible corporate pattern. That is someone who looked at the decoy
before guessing, which is a different adversary from the one running a list.

**The inverse is also a hunt.** Change `Sources == 1` to `Sources > 20` and you get the shared
wordlists instead — useful for confirming which public list is currently in circulation, and for
recognising it in someone else's environment later.

---

### Hunt 4 — What happened after a successful login

> **Hypothesis:** Getting in and doing something are different events. Most successful logins
> against a honeypot are bots that authenticate and disconnect without a single keystroke. A
> session that authenticates *and then acts* — types commands, pulls a file down, pushes a file up
> — represents an operator who is present, and is worth reconstructing keystroke by keystroke.

This one reassembles a session by joining on the session id in `DeviceCustomString1`.

```kusto
let winners = CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "login.success"
| project SessionId = DeviceCustomString1,       // session id, for sshd rows
          SourceIP,
          User = DestinationUserName,
          LoginTime = TimeGenerated;
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd"
| where DeviceEventClassID in ("command.input", "session.file_download", "session.file_upload")
| project SessionId = DeviceCustomString1, TimeGenerated, DeviceEventClassID,
          Command = DeviceCustomString3, Activity
| join kind=inner winners on SessionId           // only activity inside an authenticated session
| summarize Commands  = countif(DeviceEventClassID == "command.input"),
            Downloads = countif(DeviceEventClassID == "session.file_download"),
            Uploads   = countif(DeviceEventClassID == "session.file_upload"),
            Typed     = make_set_if(Command, isnotempty(Command), 25),
            LastAction = max(TimeGenerated)
        by SessionId, SourceIP, User, LoginTime
| extend DwellSeconds = datetime_diff('second', LastAction, LoginTime)
| order by Uploads desc, Downloads desc, Commands desc
```

**How to read it.** Sort priority is deliberate: an **upload** is the most interesting event on this
host, because it means the attacker brought something with them. Downloads mean they fetched
tooling. Commands alone mean they looked around. `DwellSeconds` separates a script that fired
instantly from a person reading output between commands.

**Note the join direction.** `winners` is the small set, filtered to one event class, and it is
summarised down to four columns before the join. Joining the raw activity rows to a small key set
is the cheap direction.

---

### Hunt 5 — Suricata signatures that almost never fire

> **Hypothesis:** An inline IDS on an internet-facing host fires the same handful of commodity
> signatures constantly — scanners, generic probes, protocol noise. A signature that fires a
> handful of times in two weeks was triggered by something outside that background, and a rare
> signature with a *high* severity is the strongest single indicator this sensor produces.

Stack counting on the IDS, and the query where `LogSeverity` being a string bites.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor == "Suricata"
| extend Severity = toint(LogSeverity)           // LogSeverity is a STRING - "10" < "5" without this
| extend Priority = DeviceCustomString1          // DeviceCustomString1 = priority, for Suricata rows
| summarize Hits = count(),
            Sources = dcount(SourceIP),
            MaxSeverity = max(Severity),
            Priorities = make_set(Priority, 5),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
        by SignatureID = DeviceEventClassID,     // "gid:signature_id", e.g. "1:2024897"
           Signature = Activity                  // the human-readable signature name
| order by Hits asc                              // rarest first
| take 40
```

**How to read it.** Read `Hits` and `MaxSeverity` together — rare *and* severe is the top-left
corner you care about. A signature with `Hits` in single digits and `Sources == 1` describes one
specific interaction, and you should pivot straight to that IP's full timeline in
`CommonSecurityLog`.

**Then pivot.** Take a `SignatureID` from the bottom of this list and re-query for every row from
its source IPs across all three vendors. The signature tells you what tripped; the pivot tells you
what they were doing either side of it.

---

### Hunt 6 — Did anything from the honeypot touch the real estate

> **Hypothesis:** The honeypot is supposed to be a dead end. If an IP that has been attacking
> `db-finance-prod01` also appears in Entra sign-in logs, in subscription control-plane activity,
> or against the public decoy site, then the decoy is no longer an isolated absorber — the same
> operator is working more than one surface, and that is a materially different situation from
> internet background noise.

This is the hunt that would matter most if it ever returned a row. It is also the expensive one.

> 💰 **This query is costly.** It scans five tables over 14 days. Run it deliberately, narrow the
> window if it is slow, and do not put it on a loop.

```kusto
let HoneypotIPs = CommonSecurityLog
| where TimeGenerated > ago(14d)
| where isnotempty(SourceIP)
| summarize HoneypotHits = count(), LastHoneypotHit = max(TimeGenerated) by SourceIP;
union isfuzzy=true
    (SigninLogs
     | where TimeGenerated > ago(14d)
     | project TimeGenerated, SourceIP = IPAddress, Surface = "SigninLogs",
               Who = UserPrincipalName, Detail = strcat(ResultType, " ", ResultDescription)),
    (AADNonInteractiveUserSignInLogs
     | where TimeGenerated > ago(14d)
     | project TimeGenerated, SourceIP = IPAddress, Surface = "AADNonInteractive",
               Who = UserPrincipalName, Detail = tostring(ResultType)),
    (AzureActivity
     | where TimeGenerated > ago(14d)
     | project TimeGenerated, SourceIP = CallerIpAddress, Surface = "AzureActivity",
               Who = Caller, Detail = OperationNameValue),
    (AppServiceHTTPLogs
     | where TimeGenerated > ago(14d)
     | project TimeGenerated, SourceIP = CIp, Surface = "AppServiceHTTPLogs",
               Who = "n/a", Detail = strcat(CsMethod, " ", CsUriStem))
| join kind=inner HoneypotIPs on SourceIP        // small summarised set on the right
| summarize Events = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            Identities = make_set(Who, 5),
            Examples = make_set(Detail, 5)
        by SourceIP, Surface, HoneypotHits
| order by Surface asc, Events desc
```

**How to read it, carefully.** A hit on `AppServiceHTTPLogs` is expected and mild — both the
honeypot and the decoy site are internet-facing, and the same scanners sweep both. That is
correlation worth noting, not an incident. A hit on `SigninLogs` or `AzureActivity` is a different
category entirely: those surfaces have no reason to see traffic from a honeypot attacker, and a row
there needs an investigation opened, not a bookmark.

**Do not skip the sanity check.** Before treating any row as a finding, confirm the IP is not
yours. Operator activity from a shared or rotating egress address correlates with everything, and
mistaking your own testing for an adversary is the most common way a hunt produces a confident
wrong answer.

---

### Hunt 7 — Sources that got past more than one door

> **Hypothesis:** Traffic hits this host through layered sensors — firewall, then IDS, then the
> application shell. Most sources are stopped at the first one and never appear again. A source
> observed at multiple doors travelled *through* the stack rather than bouncing off it, and the
> depth an IP reached is a better ranking signal than how much noise it made at the perimeter.

The newest field in the schema, and the one that makes the traffic path queryable.

> ⚠️ **`DeviceEventCategory` was added 2026-08-22.** Rows ingested before that carry an empty
> value and drop out of the `isnotempty()` filter, so this hunt's real window starts on that date
> regardless of the `ago()` you set. A short result is a young field, not a quiet host.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(3d)
| where isnotempty(DeviceEventCategory)          // field exists only on data from 2026-08-22 onward
| extend Door = tostring(split(DeviceEventCategory, " - ")[0])   // "Door 2" / "Door 3" / "Door 4"
| summarize DoorsReached = dcount(Door),
            Doors    = make_set(Door),
            Sensors  = make_set(DeviceVendor),
            Denied   = countif(DeviceAction == "Denied"),
            Allowed  = countif(DeviceAction == "Allowed"),
            Events   = count(),
            LastSeen = max(TimeGenerated)
        by SourceIP
| where DoorsReached >= 2                        // got past one sensor - not a single blocked packet
| order by DoorsReached desc, Allowed desc
```

**How to read it.** Rank by `DoorsReached` first and `Events` last. An IP with three doors and forty
events is more interesting than an IP with one door and four thousand — depth beats volume, and
this is the clearest example on the page of why the loudest row is rarely the important one. Any
source reaching `Door 4` has interacted with the shell, which means [Hunt 4](#hunt-4--what-happened-after-a-successful-login)
should be run against it next.

---

### Hunt 8 — The hunt that validates the other seven

> **Hypothesis:** A sensor that stops shipping produces no error, no alert, and no incident — it
> produces *silence*, which is indistinguishable from a quiet week. If any source in this workspace
> has gone dark, then every hunt above returns fewer rows for a reason that has nothing to do with
> attacker behaviour, and I would not know unless I looked directly.

Run this **before** you trust an empty result from anything else on this page.

```kusto
// Per-sensor freshness inside the CEF feed - a vendor that stopped shipping is otherwise invisible
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize Events = count(), LastSeen = max(TimeGenerated) by DeviceVendor, Computer
| extend MinutesQuiet = datetime_diff('minute', now(), LastSeen)
| order by MinutesQuiet desc
```

Three vendors ship to this table — `sshd`/`telnetd`, `Suricata`, and `nftables`. A vendor missing
from these results entirely has been silent for the whole window, which is the failure mode this
query exists to catch, and it is easy to miss because a missing row draws no attention.

Then check the agents themselves:

```kusto
Heartbeat
| where TimeGenerated > ago(7d)
| summarize LastSeen = max(TimeGenerated) by Computer, Category
| extend MinutesQuiet = datetime_diff('minute', now(), LastSeen)
| order by MinutesQuiet desc
```

**A gap you already have.** Sysmon on the Arc-connected laptop has been down since **2026-08-07**.
Any hunt over `SecurityEvent` that depends on Sysmon event IDs will return nothing, and that
nothing means "not collected", not "not happening". Worth doing the arithmetic: with 30-day
retention, the last Sysmon data ages out of this workspace around **2026-09-06**, after which the
gap stops being visible as a gap at all — the table will simply look as though it never had that
telemetry. A blind spot you have written down is a known limitation; the same blind spot
unrecorded is a wrong conclusion waiting to happen.

---

## 🧾 Turning a hunt into something that lasts

A hunt that keeps finding the same real thing should stop being a hunt. Conversion is not
copy-paste:

| Hunting query | Analytics rule |
|---|---|
| Wide window, e.g. `ago(14d)` | narrow, matching the rule's query period |
| Any number of rows is fine | needs a threshold that means something |
| No entity mapping | **requires** entity mappings, or the incident is uninvestigable |
| Ordered ascending to find the rare | usually needs re-orienting — rules fire on presence, not rarity |
| You read the result | it runs unattended, forever |

Remove the `ago()` — the rule scopes its own time window, and leaving both in produces a rule whose
real window is the intersection of the two. Then ask the judgement question: **is this still
interesting when it fires at 3am and nobody is reading?** A stack count is a poor rule precisely
because rarity is the point, and a rule that alerts on everything rare alerts constantly.

The [detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
holds the 38 rules that survived that conversion. The
[hunt program](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/THREAT-HUNTING-LIBRARY/README.md)
holds the hunts, mapped to MITRE tactics and written up with their results — including the ones
that found nothing, and the ones that turned out to be the lab operator's own activity. Both
outcomes get recorded there. That habit — separating what the query returned from what you think it
means — is the part of hunting that is actually hard, and it is worth more than any query on this
page.

---

## ✅ Practice checklist

| # | Do this | Done |
|--:|---|:--:|
| 1 | Run Hunt 8 first and confirm all three CEF vendors are current | ☐ |
| 2 | Run Hunt 1 both ways — ascending, then descending — and write down the difference | ☐ |
| 3 | Run Hunt 2 and verify the baseline window actually has data before trusting an empty result | ☐ |
| 4 | Take one rare command from Hunt 1 and pivot to that source IP's full timeline | ☐ |
| 5 | Run Hunt 6 once and confirm whether any honeypot IP reaches a real surface | ☐ |
| 6 | Write one hypothesis of your own, in the four-part form, before writing its KQL | ☐ |
| 7 | Contribute the result to [`THREAT-HUNTING-LIBRARY/`](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/THREAT-HUNTING-LIBRARY/README.md) — observation and interpretation kept separate | ☐ |

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Hunt program](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/THREAT-HUNTING-LIBRARY/README.md) &nbsp;·&nbsp; [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
