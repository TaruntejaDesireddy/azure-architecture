# Working in this repo

A personal roadmap, not an open-source project — these are the conventions that keep it useful.

## The rules that matter

**1. Material goes in [`azure-soc-lab`](https://github.com/TaruntejaDesireddy/azure-soc-lab); only pointers and your own work go here.**
If you catch yourself writing a how-to in this repo, it belongs there instead, with a link added
here. Two copies of one explanation is the problem this split exists to avoid.

**2. Never fabricate.** No invented completion status, certification status, screenshots, test
results or security findings. An untouched module says *not started*; a control you have not tested
says so. A checklist that records intention rather than fact is worse than no checklist.

**3. Stage 4 is isolated-lab only.** The progression includes deliberately misconfiguring things.
That happens on disposable resources, never on anything internet-reachable or shared.

## What belongs where

| Here | In `azure-soc-lab` |
|---|---|
| Area checklists and stage tracking | The explanation of a topic |
| Links to the real material | Portal click-paths, KQL, scripts |
| Your own scripts, queries, artifacts | Anything reusable at a client |
| Capstone architectures and lab writeups | The build record and decisions |

## Links

Cross-repo links use the full `https://github.com/TaruntejaDesireddy/azure-soc-lab/blob/main/...` form and resolve only while signed in — the
target repo is private. Open a link once before adding it; a roadmap full of 404s is worse than a
short one.

## Cost

Several areas cover services that bill hourly — Azure Firewall, Application Gateway, Bastion,
Defender plans. Deploy, use, **delete the same day**. Record the teardown in your notes.
