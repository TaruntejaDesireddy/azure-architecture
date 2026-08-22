# Optimization

> **The optimization material lives in [`../performance/README.md`](../performance/README.md).**

Performance and optimization were written as one page because on a **$15/month** budget they are
the same subject — a slow query and an expensive query are usually the same query.

That page is seven rules, each with a before/after:

| Rule | |
|---|---|
| 1 | Time first, then the most selective filter |
| 2 | `==`, then `has`, then `contains`, then regex |
| 3 | Never `search *` |
| 4 | Project early, drop what you will not read |
| 5 | Summarize before you join |
| 6 | It is the `*` in `union withsource = X *`, not the `withsource` |
| 7 | Scout before you commit |

Put your own tuned queries and measurements here.
