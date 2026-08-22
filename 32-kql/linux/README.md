# Linux — `Syslog`

> **The Linux queries live in [`../windows/README.md`](../windows/README.md).**

Both endpoint sources are documented together because the interesting lesson is the *contrast*
between them, and splitting it across two files would have meant explaining the same thing twice:

| Source | Table | Covered in |
|---|---|---|
| Windows endpoint (Arc-connected laptop) | `SecurityEvent` | [windows/README.md](../windows/README.md#-securityevent--the-windows-endpoint) |
| Honeypot host (`db-finance-prod01`) | `Syslog` | [windows/README.md](../windows/README.md#-syslog--the-honeypot-host) |

That file also answers the question this folder would otherwise raise: **why this lab's detections
query `CommonSecurityLog` and not `Syslog`**, even though both carry the same host's activity.

Put your own Linux-specific queries here as you write them.
