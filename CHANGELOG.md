# Changelog

## 2026-08-22 — created

Built from the *Azure Security Engineer — Master Repository* design document.

- 61 module folders (`00`–`60`) with 679 area subfolders from the design.
- 36 capstone architectures, attack/defense labs and real-world scenarios captured as
  tracked items where the document listed IDs rather than folders.
- 181 cross-links into [`azure-soc-lab`](https://github.com/TaruntejaDesireddy/azure-soc-lab), each verified against a real file before
  being written.
- The nine-stage progression (Understand → Deploy → Secure → Misconfigure → Detect → Investigate
  → Remediate → Automate → Architect) added to every module as a checklist, per the design's own
  instruction not to produce shallow documentation.
- `certification-mapping/` for SC-300, SC-200, SC-100 and AZ-500.

Parsing notes: the document mixed folder trees with prose and ID lists. Module 60's section ran a
taxonomy list straight into its folder tree, which the first parse turned into folder names like
`Compute/Storage/DB` — those were filtered out, leaving its 10 real folders.
