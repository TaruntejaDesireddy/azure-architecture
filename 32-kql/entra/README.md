# 32 · entra — KQL query library for identity

![Area](https://img.shields.io/badge/Area-entra-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Tables](https://img.shields.io/badge/Tables-5-0078D4?style=flat-square)
![Queries](https://img.shields.io/badge/Queries-12-0078D4?style=flat-square)

> Query library for the five Entra ID tables in **`la-lab-eus-01`**. Every query below is written
> against tables and columns this workspace actually populates — no invented schema.

Identity is the quietest source in this lab. The honeypot's `CommonSecurityLog` feed is loud and
continuous; Entra is a handful of sign-ins a day from one operator and some automation. That makes
it the *best* place to learn identity KQL — a single deliberate event is easy to find, and anything
you did not cause yourself is genuinely worth a look.

Six of the lab's 38 deployed analytics rules read these tables. Their exported definitions are in
the [detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md) —
several queries here are the hunting-shaped version of a rule that already runs on a schedule.

---

## 🧭 What is in these five tables

| Table | What lands in it | Why you would open it |
|---|---|---|
| `SigninLogs` | Interactive user sign-ins | The obvious one — a human typed a password |
| `AADNonInteractiveUserSignInLogs` | Token refresh, silent re-auth | Where **stolen-token** activity lives; far higher volume than interactive |
| `AADServicePrincipalSignInLogs` | App / daemon authentication | Workload identities — no human, no MFA, often over-permissioned |
| `AADManagedIdentitySignInLogs` | Managed identity auth | The lab's own automation. Anomalies here mean scripted access changed |
| `AuditLogs` | Every directory **change** | Role grants, app consent, credential adds — the post-compromise half |

The split that catches people out: sign-in tables answer *"who authenticated"*, `AuditLogs` answers
*"what changed afterwards"*. An account takeover is visible in both, and the interesting part is
usually the second one.

---

## 🪪 Licence gates — which of these have data here

This tenant runs **Entra ID Free**. That matters, and it is not a defect to work around — knowing
precisely which telemetry your tier produces is the point of the exercise.

| Column / table | Tier needed to *produce data* | State in this workspace |
|---|---|---|
| `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs` | Free | Populated |
| `ConditionalAccessStatus`, `AuthenticationRequirementPolicies` | **P1** — Conditional Access is a P1 feature | Column exists; reads `notApplied` because no CA policy can exist |
| `RiskLevelDuringSignIn`, `RiskLevelAggregated`, `RiskState`, `RiskDetail`, `RiskEventTypes_V2` | **P2** — Identity Protection | Columns exist; sit at `none` / `hidden` and never move |
| `AADRiskyUsers`, `AADUserRiskEvents`, `AADRiskyServicePrincipals`, `AADServicePrincipalRiskEvents` | **P2** | Not populated — no query below depends on them |

> **Ticking a diagnostic-settings category is not the same as receiving data.** The Identity
> Protection categories export happily on Free and are simply always empty. Query 8 below is written
> so that its emptiness *is* the finding — an empty result there is the licence gate, not a broken
> query.

Practical consequence for the queries here: anything risk-based is a **shape to learn**, not a
detection that will fire in this tenant. Everything else is live.

---

## ⚠️ Six things that will bite you before the KQL does

| Gotcha | What to do |
|---|---|
| `ResultType` is a **string**, not a number | Compare against `"0"`, never `0`. Success is `"0"`. (Same trap as `LogSeverity` in `CommonSecurityLog` — use `toint()` there.) |
| `Status`, `LocationDetails`, `DeviceDetail`, `InitiatedBy`, `TargetResources` are **dynamic** | Reach in with `tostring()` / `todouble()`. A bare `Status.errorCode` in a `summarize by` will surprise you |
| `UserPrincipalName` casing is inconsistent | Use `=~` for comparisons, or `tolower()` before a `join` |
| Workspace retention is **30 days** | A 90-day baseline silently returns 30 days of data, not an error. Never build a "normal" baseline you cannot actually reach |
| `AuditLogs` actors live in two places | A human is `InitiatedBy.user.userPrincipalName`; an app is `InitiatedBy.app.displayName`. Read only one and half your results look anonymous |
| Non-interactive volume dwarfs interactive | Do not compare raw counts between the two tables and conclude anything |

---

## 💸 What these queries cost

Straight answer: **interactive queries against these tables are not billed.** Log Analytics charges
for ingestion and retention, not per query, and all five Entra tables are Analytics-tier here. You
can iterate on the queries below all day for $0.

What that budget line actually protects against:

- **Ingestion**, and Entra is not the threat — these five tables are a rounding error next to the
  honeypot's continuous CEF feed.
- **A wasteful query promoted to a scheduled analytics rule**, which then re-runs that scan forever.
  Get the time window tight *before* you turn a hunt into a rule.
- **Your own time.** An unfiltered `union` over 30 days will sit there.

One query on this page is genuinely heavy — the [cross-over query](#-crossing-over-to-the-honeypot)
at the end scans `CommonSecurityLog`, the richest table in the workspace. It is flagged again where
it appears.

---

## 🔎 The query library

### 1 — What identity data is actually arriving?

Run this first, always. It answers *"is the pipeline healthy"* before you conclude that an empty
result means nothing happened. A missing row means that category is not being delivered.

```kusto
// isfuzzy=true so a table that has never received data warns instead of failing the whole query
union isfuzzy=true
    SigninLogs,
    AADNonInteractiveUserSignInLogs,
    AADServicePrincipalSignInLogs,
    AADManagedIdentitySignInLogs,
    AuditLogs
| where TimeGenerated > ago(24h)
| summarize Records = count(), Newest = max(TimeGenerated) by Type
| order by Records desc
```

If `SigninLogs` is missing but `AuditLogs` is present, the diagnostic setting is only half
configured — they are separate categories.

---

### 2 — Failed sign-ins, grouped by user

Answers *"which account is being hammered, and with what kind of failure"*. Grouping by user rather
than by event turns thousands of rows into a list you can read.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"                          // string compare - "0" is success
| extend ErrorCode = tostring(Status.errorCode)
| summarize Failures   = count(),
            SourceIPs  = dcount(IPAddress),
            Codes      = make_set(ErrorCode, 5),   // 50126 = bad password, 50053 = smart lockout
            Apps       = make_set(AppDisplayName, 5),
            FirstSeen  = min(TimeGenerated),
            LastSeen   = max(TimeGenerated)
        by UserPrincipalName
| order by Failures desc
```

Read `Codes` before you panic. `50126` repeating from one IP is a guess; `50055` (expired password)
and `50058` (silent sign-in failed) are noise.

---

### 3 — Password spray shape: one source, many accounts

Answers *"is a single IP trying a few passwords against lots of accounts"* — the inverse of brute
force, and the reason a per-user failure threshold misses it entirely. Spray is defined by breadth
across accounts, not depth against one.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Failures      = count(),
            TargetedUsers = dcount(UserPrincipalName),
            Users         = make_set(UserPrincipalName, 20),
            Countries     = make_set(Country, 5)
        by IPAddress, bin(TimeGenerated, 1h)
| where TargetedUsers >= 3                         // breadth, not depth, is the spray signal
| order by TargetedUsers desc, Failures desc
```

The deployed rule that covers this fires on 5+ failures from one IP in an hour. This hunting version
lowers the bar and adds the distinct-user count, which is the part that distinguishes spray from a
user with a stale saved password.

---

### 4 — Impossible travel shape

Answers *"did this account authenticate from two places further apart than a person could travel"*.
Without P2 there is no Identity Protection detection to lean on, so you compute it yourself — which
is a better way to learn what the signal actually is.

```kusto
let LookBack    = 7d;
let MinKph      = 900.0;    // faster than a commercial flight
let MinDistance = 500.0;    // km - below this, geo-IP error dominates
SigninLogs
| where TimeGenerated > ago(LookBack)
| where ResultType == "0"                          // only successful sign-ins can be "travel"
| extend Country = tostring(LocationDetails.countryOrRegion),
         City    = tostring(LocationDetails.city),
         Lat     = todouble(LocationDetails.geoCoordinates.latitude),
         Lon     = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotnull(Lat) and isnotnull(Lon)          // not every sign-in carries coordinates
| sort by UserPrincipalName asc, TimeGenerated asc  // sort serializes, which prev() requires
| extend PrevUser    = prev(UserPrincipalName),
         PrevTime    = prev(TimeGenerated),
         PrevLat     = prev(Lat),
         PrevLon     = prev(Lon),
         PrevCity    = prev(City),
         PrevCountry = prev(Country)
| where PrevUser =~ UserPrincipalName              // discard the boundary between two users
| extend GapHours = (TimeGenerated - PrevTime) / 1h
| where GapHours > 0
| extend DistanceKm = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000   // returns metres
| extend ImpliedKph = DistanceKm / GapHours
| where DistanceKm > MinDistance and ImpliedKph > MinKph
| project TimeGenerated, UserPrincipalName,
          From = strcat(PrevCity, ", ", PrevCountry), To = strcat(City, ", ", Country),
          DistanceKm = round(DistanceKm, 0), GapHours = round(GapHours, 2),
          ImpliedKph = round(ImpliedKph, 0), IPAddress
| order by ImpliedKph desc
```

The complexity here is earning its place: `sort` + `prev()` is what pairs each sign-in with the same
user's previous one, and the `PrevUser =~ UserPrincipalName` guard is what stops the last row of one
user pairing with the first row of the next. Expect VPN and mobile-carrier egress to generate most
of what you find.

---

### 5 — A country this user has never signed in from

Answers *"is this location new for this specific person"*, which is a far better question than
"is this location unusual for the tenant". Everyone's normal is different.

```kusto
let Baseline = 14d;   // what normal looks like for each user
let Recent   = 1d;    // the window being judged
let Known =
    SigninLogs
    | where TimeGenerated between (ago(Baseline) .. ago(Recent))
    | where ResultType == "0"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | distinct UserPrincipalName, Country;
SigninLogs
| where TimeGenerated > ago(Recent)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion),
         City    = tostring(LocationDetails.city)
| where isnotempty(Country)
| join kind=leftanti Known on UserPrincipalName, Country   // leftanti = keep only what is NOT known
| project TimeGenerated, UserPrincipalName, Country, City, IPAddress, AppDisplayName, ClientAppUsed
| order by TimeGenerated desc
```

`leftanti` is the operator worth internalising — "rows on the left with no match on the right" is the
shape of most first-seen hunting. Remember the baseline cannot exceed 30 days of retention here.

---

### 6 — Legacy authentication

Answers *"did anything authenticate over a protocol that cannot do MFA"*. Legacy auth is how an
attacker with a valid password sidesteps MFA entirely, which is why it matters even when every
attempt fails.

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "Other clients",
                          "Authenticated SMTP", "IMAP", "SMTP", "MAPI over HTTP",
                          "Offline Address Book")
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Attempts  = count(),
            Succeeded = countif(ResultType == "0"),   // this is the column that matters
            IPs       = make_set(IPAddress, 10),
            Countries = make_set(Country, 5)
        by UserPrincipalName, ClientAppUsed
| order by Succeeded desc, Attempts desc
```

`Succeeded > 0` is an incident. `Succeeded == 0` with high `Attempts` is someone probing, which is
still worth knowing. Re-run the same query against `AADNonInteractiveUserSignInLogs` — legacy
protocols frequently log there instead, and checking only the interactive table under-reports.

---

### 7 — MFA outcomes

Answers *"was a second factor required, and what happened when it was"*. On this tenant MFA comes
from Security Defaults rather than a Conditional Access policy, so `AuthenticationRequirement` is the
honest column to group by.

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| extend ErrorCode = tostring(Status.errorCode)
| summarize Attempts            = count(),
            Success             = countif(ResultType == "0"),
            MfaNotSatisfied     = countif(ErrorCode == "50074"),   // prompted, never completed
            MfaRequiredByPolicy = countif(ErrorCode == "50076"),
            BlockedByCA         = countif(ErrorCode in ("53003", "530031"))
        by UserPrincipalName, AuthenticationRequirement
| order by Attempts desc
```

`AuthenticationRequirement` reads `singleFactorAuthentication` or `multiFactorAuthentication`.
`BlockedByCA` will stay at zero here — those codes need P1 Conditional Access to ever appear, and the
column is in the query so the shape is complete, not because it will populate.

A cluster of `MfaNotSatisfied` against one account, from an IP that also succeeded at first factor,
is the classic "password is known, second factor is not" signal — the moment to reset the password
rather than wait.

---

### 8 — Risky sign-ins *(needs P2 — will be empty here)*

Answers *"what did Identity Protection think of this sign-in"*. Included so the shape is in the
library, and so the empty result teaches the licence gate.

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| extend Country = tostring(LocationDetails.countryOrRegion)
// isnotempty() first: a null risk column would drop out of !in() silently
| where isnotempty(RiskLevelDuringSignIn) and RiskLevelDuringSignIn !in ("none", "hidden")
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName,
          RiskLevelDuringSignIn, RiskLevelAggregated, RiskState, RiskDetail, RiskEventTypes_V2,
          ResultType
| order by TimeGenerated desc
```

**This returns nothing in `la-lab-eus-01`, and that is correct.** The columns exist on every tier;
Identity Protection only writes values into them with Entra ID P2. To prove the gate rather than
assume it, run `SigninLogs | summarize count() by RiskLevelDuringSignIn` over 30 days — every row
will be `none` or `hidden`. That single result is a better answer to "do we have risk detection" than
any amount of documentation.

---

### 9 — Non-interactive sign-ins from somewhere the user never interactively signs in

Answers *"is a refresh token being replayed from somewhere the human has never been"*. This is the
table's whole reason for existing: a stolen token refreshes silently and never touches the
interactive log, so an investigation that only opens `SigninLogs` will find nothing.

```kusto
let InteractiveCountries =
    SigninLogs
    | where TimeGenerated > ago(30d)                  // capped by workspace retention
    | where ResultType == "0"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | distinct UserPrincipalName, Country;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| join kind=leftanti InteractiveCountries on UserPrincipalName, Country
| summarize Refreshes = count(),
            Apps      = make_set(AppDisplayName, 10),
            IPs       = make_set(IPAddress, 10),
            LastSeen  = max(TimeGenerated)
        by UserPrincipalName, Country
| order by Refreshes desc
```

Same `leftanti` shape as query 5, pointed at a different table — that reuse is deliberate, learn the
pattern once. For plain volume orientation instead, drop the `join` and summarise by
`UserPrincipalName` alone.

---

### 10 — Workload identities: service principals and managed identities

Answers *"which non-human identity authenticated, to what, and did it fail"*. Service principals have
no MFA and no user behind them, so a failure spike usually means an expired secret — or someone
trying a credential that no longer works.

```kusto
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| summarize Attempts  = count(),
            Failures  = countif(ResultType != "0"),
            IPs       = make_set(IPAddress, 10),
            Resources = make_set(ResourceDisplayName, 10),
            LastSeen  = max(TimeGenerated)
        by ServicePrincipalName, AppId
| order by Failures desc, Attempts desc
```

Managed identities are the same question with a different caller. Note there is no useful source IP
in this table — the caller is Azure itself — so the query does not pretend otherwise:

```kusto
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(7d)
| summarize Attempts  = count(),
            Failures  = countif(ResultType != "0"),
            Resources = make_set(ResourceDisplayName, 10),
            LastSeen  = max(TimeGenerated)
        by ServicePrincipalName, ServicePrincipalId
| order by Attempts desc
```

This is the lab's own automation showing up. Establish what *should* be here before you judge
anything on it as suspicious — a new `ServicePrincipalName` you did not deploy is the finding.

---

### 11 — Directory role changes

Answers *"who was granted a privileged role, by whom"*. This is the single highest-value query in the
file: it is the step that turns a compromised account into a compromised tenant.

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Remove member from role",
                          "Add eligible member to role", "Remove eligible member from role")
| extend Targets = parse_json(TargetResources)
| mv-expand Targets
| extend ModProps = parse_json(Targets.modifiedProperties)
| mv-expand ModProps
// the role name is buried in modifiedProperties, not in a top-level column
| where tostring(ModProps.displayName) == "Role.DisplayName"
| extend RoleName = trim('"', tostring(ModProps.newValue))   // the value arrives JSON-quoted
| extend ActorUser = tostring(parse_json(InitiatedBy).user.userPrincipalName),
         ActorApp  = tostring(parse_json(InitiatedBy).app.displayName)
| extend Initiator   = iff(isnotempty(ActorUser), ActorUser, ActorApp),  // human or app
         InitiatorIP = tostring(parse_json(InitiatedBy).user.ipAddress),
         Target      = tostring(Targets.displayName)
| project TimeGenerated, OperationName, RoleName, Target, Initiator, InitiatorIP, Result
| order by TimeGenerated desc
```

The double `mv-expand` is doing real work — `TargetResources` is an array, and each target carries
its own `modifiedProperties` array. Without both, the role name is unreachable.

To narrow to the roles that matter, add:

```kusto
| where RoleName in ("Global Administrator", "Privileged Role Administrator",
                     "Security Administrator", "User Administrator",
                     "Application Administrator", "Cloud Application Administrator",
                     "Conditional Access Administrator", "Privileged Authentication Administrator")
```

The eligible-member operations only produce rows with PIM, which is P2 — they are in the filter so
the query stays correct if the tier ever changes, not because they will match today.

---

### 12 — App consent and permission grants

Answers *"did someone consent to an application, and what did they hand it"*. This is the mechanism
behind illicit consent-grant phishing: no password is stolen, the victim simply approves an app that
then reads their mail with its own token.

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Consent to application", "Add app role assignment to service principal",
                          "Add delegated permission grant", "Add OAuth2PermissionGrant",
                          "Add service principal credentials")
| extend ActorUser = tostring(parse_json(InitiatedBy).user.userPrincipalName),
         ActorApp  = tostring(parse_json(InitiatedBy).app.displayName)
| extend Initiator   = iff(isnotempty(ActorUser), ActorUser, ActorApp),
         InitiatorIP = tostring(parse_json(InitiatedBy).user.ipAddress)
| mv-expand Target = TargetResources
| extend AppName = tostring(Target.displayName)
// read modifiedProperties whole rather than filtering on a property name -
// the name differs per operation, and a wrong literal returns zero rows that look like "all clear"
| extend Granted = tostring(Target.modifiedProperties)
| project TimeGenerated, OperationName, AppName, Initiator, InitiatorIP, Result, Granted
| order by TimeGenerated desc
```

`Granted` is raw JSON on purpose — read it. Once you know what the scopes look like in your own
tenant, narrow with a line like:

```kusto
| where Granted has_any ("Mail.Read", "Mail.ReadWrite", "Mail.Send",
                         "Files.ReadWrite.All", "Directory.ReadWrite.All", "offline_access")
```

`offline_access` is the one people skip over. It is what lets the app keep a refresh token and come
back without the user, which is the entire point of the attack.

---

## 🔗 Crossing over to the honeypot

Answers *"is an IP that failed to sign in to Entra the same IP that is attacking the honeypot"*. A
genuine cross-source pivot, and the payoff for having both feeds in one workspace.

> **This is the expensive query on this page.** It scans `CommonSecurityLog` — the richest table in
> `la-lab-eus-01` — across 7 days. Tighten the window before you run it repeatedly, and tighten it
> hard before you ever schedule it.

```kusto
let EntraFailIPs =
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType != "0"
    | where isnotempty(IPAddress)
    | distinct IPAddress;
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where SourceIP in (EntraFailIPs)                 // the join is a cheap IP set, not a table join
| summarize Events    = count(),
            Sensors   = make_set(DeviceVendor, 5),          // sshd / telnetd / Suricata / nftables
            Doors     = make_set(DeviceEventCategory, 5),   // which layer it reached
            Usernames = make_set(DestinationUserName, 10),
            LastSeen  = max(TimeGenerated)
        by SourceIP
| order by Events desc
```

Set realistically: the honeypot takes broad internet scanning while Entra sees a very small,
mostly-operator population, so a hit here is uncommon — and correspondingly interesting when it
happens. An empty result is the normal outcome, not a failure.

---

## 🪜 Suggested order to work through this

| # | Do this | You will have learned |
|--:|---|---|
| 1 | Run query 1, confirm all five tables report | The pipeline, before trusting any result |
| 2 | Run queries 2, 3, 6 over 24h | `summarize`, `countif`, `make_set`, and why string `ResultType` matters |
| 3 | Fail a sign-in deliberately, find it | That you can generate and locate a known event |
| 4 | Run query 8, confirm it is empty, prove why | The P2 gate, from evidence rather than documentation |
| 5 | Assign a low-impact directory role, find it with query 11 | Nested `mv-expand` against `TargetResources` |
| 6 | Run queries 4, 5, 9 | `prev()` serialisation and the `leftanti` first-seen pattern |
| 7 | Compare one query here to its deployed rule | The difference between a hunt and a scheduled detection |

Step 7 is the one that matters most. A query that has never matched a real event is a hypothesis, not
a detection.

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)
