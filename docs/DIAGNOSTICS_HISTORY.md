# Diagnostics history

## Historical CPU report retained on purpose

The file `docs/diagnostics/2026-04-15_v23_cpu_baseline.md` is intentionally kept in the repository.
It is **not** the current architecture description; it is a historical diagnostic baseline collected
against `myprox_project_v23_optimized_sqlite` before the later selective-interception refactor.

### What is still useful from that report

- The measured CPU floor was dominated by **kernel-mode** time, which strongly indicated
  interception/reinjection overhead rather than WebUI, JSON, JavaScript, or SQLite work.
- Increasing the owner-cache refresh interval did **not** materially reduce the CPU floor.
  That means owner-cache refresh was a secondary cost, not the primary bottleneck.
- The report correctly identified the most important optimization priority: a **true `Direct`
  fast-path** and an operating mode that avoids full transparent routing when the effective
  configuration is all-`Direct`.

### What became outdated later

The historical report states that:

- all outbound TCP was intercepted globally at the WinDivert network layer;
- `Direct` still paid the full transparent redirect + local relay path.

Those statements were accurate for the measured v23 revision, but later revisions changed the design.
The current architecture document is the source of truth for the current code.

### How to use the report today

Treat it as:

- evidence for **why** the selective-interception design exists;
- a benchmark baseline for future regressions;
- a reminder that any regression which reintroduces always-on packet interception for `Direct`
  traffic is very likely to increase CPU again.

Do **not** treat it as the canonical description of the current hot path.
