# Security

This repository contains **no credentials, secrets, tenant identifiers or customer data**, and must
not acquire any.

## What must never be committed here

| Never | Why |
|---|---|
| Tenant IDs, subscription IDs, object IDs | Identifies a real environment |
| Keys, secrets, SAS tokens, connection strings | Immediate compromise |
| Screenshots showing real resource names or IPs | Same as above, harder to spot |
| Client names or engagement details | Contractual, not just technical |
| Real findings from an employer's environment | Belongs to them, not to a personal repo |

The lab this roadmap points at ([`azure-soc-lab`](https://github.com/TaruntejaDesireddy/azure-soc-lab)) *does* contain real identifiers and is
private for that reason. Keep the boundary: pointers here, particulars there.

## Lab safety

The progression in each module includes a deliberate misconfiguration stage. That is for
**isolated, disposable lab resources only** — never anything internet-reachable, shared, or
holding real data. Tear it down the same day.

## Reporting

Personal repository — if you find something wrong in it, fix it and note it in `CHANGELOG.md`.
