# Release candidate review (Checkpoint 7)

Prepared 2026-11-15 for the go/no-go decision. This page says what has been shown to work, what has
not, and what I recommend. The evidence for each item is in `tasks/todo.md` (each task has its
notes, measurements and limits) and in the guides under `docs/`.

## Verification just run

| Check | Result |
|---|---|
| Working tree | Clean, everything committed and pushed to `main` |
| `scripts\check.ps1` (format, clippy with warnings as errors, all tests) | Passed: about 600 tests across the seven crates |
| `cargo audit` (1,509 advisories, 319 crates) | No vulnerabilities, no warnings |
| `scripts\net-check.ps1` | One listener on 127.0.0.1, no connection to any other address, no UDP |
| Release build | Builds; `winperf`, `winperf-service`, `winperf-report` |

## Requirement coverage

| PRD | Status | Notes |
|---|---|---|
| FR-001 to FR-004 inventory, classification, processes, application association | Done | Walkthrough items 1 to 3 seen working by you. Not every program registers as an installed application, so some rank by executable. |
| FR-005, FR-006, FR-009 CPU, memory, system-wide | Done | |
| FR-007 disk | Done, with a caveat | Per-process disk is all I/O the process does, not only the physical disk (stated in the UI and `docs/limitations.md`). Per-process attribution to a physical disk is deferred (decided at Checkpoint 0). |
| FR-008 network | Done, needs administrator | Per-process network uses an event trace and needs administrator rights (the service has them). Shown as "not measured", never zero. |
| FR-010 to FR-013 baselines, confidence | Done | Three rolling windows (1 h, 24 h, 7 d) with confidence levels and a learning mode. FR-012's contextual baselines (time of day, day of week) are explicitly "eventually" in the PRD and are not built. |
| FR-014 to FR-018 detection, statistics, memory leaks, correlation, classification | Done | Thresholds are tuned but **not signed off over a real day of use** (Checkpoint 4, open). |
| FR-019 notifications | Partly | Terminal notifications (line and bell), historical records, and the dashboard's active-anomaly card are done. The optional Windows notifications are not built. |
| FR-020, FR-021 terminal application and commands | Done | Ratatui dashboard with the views listed in the guide; full command set. |
| FR-022 to FR-027 browser report | Done | Dashboard, charts, rankings, application detail, anomaly pages. Deviations from the PRD wording: **Tailwind CSS instead of Topcoat** and default **port 8099 instead of 8080** (both decided earlier). |
| FR-028 export | Done | CSV and JSON for history, anomalies and rankings; formula-safe CSV. |
| Section 4 storage, 4.3 retention | Done | SQLite, migrations; retention is **deliberately shorter than the PRD's defaults** (raw 2 days, 1-minute rows 14 days, 15-minute rows 180 days) with rollups, to keep the file near 5 GB. |
| Section 5.3 service | Done | LocalSystem, delayed auto-start, recovery restarts, single-recorder lock. Install/uninstall verified by you in Phase 5; crash recovery tested. |
| NFR-001 performance | Met in a 12-minute measurement | 0.70 % of one core, 26 MB. The 24-hour service run is open. |
| NFR-002 reliability | Done, partly measured | Crash and kill recovery tested; transactions throughout; the 24-hour unattended run is open. |
| NFR-003 security | Done | Restricted data folder, no stored command lines (and redaction where shown), localhost by default, token required for other binds, no outside connections. No TLS. |
| NFR-004, NFR-005 | Done | Seven separated crates; the engine is independent of the front ends. |

## Open items

1. **Checkpoint 4: a real day of use and your sign-off on detection sensitivity.** The thresholds
   (including the memory rule tuned after the first live run) have been checked on synthetic cases
   and one live session of about five hours, not a full day of ordinary use. This is the item most
   likely to change how the product feels: too many or too few anomalies.
2. **Checkpoint 5 and the rest of T36: a 24-hour unattended run of the installed service**
   (terminal closed, data continuous, overhead recorded). Command: install the service, then
   `.\scripts\overhead.ps1 -Hours 24`. Also covers sampling with nobody logged in, restart after a
   kill, and a reboot.
3. **Checkpoint 1's note** ("human reviews real inventory output for classification errors"):
   walkthrough items 1 to 3 were ticked, which I take as that review; say if you want a closer pass
   at the classifications.
4. **Fresh-machine install.** The guide was written from the commands, not tested on a clean
   machine. There is no installer: it is `cargo build` and copy.

## Known limitations that affect a go decision

(Full list in `docs/limitations.md`.)

- No TLS on the report; remote access is for trusted networks only.
- Peaks and averages from the older (rollup) history are smoothed.
- Long ranges are sampled for speed (the page says so).
- The service does not start the browser report; it is a separate program.
- A detection tuned on one machine will behave differently on another.
- The Windows service and the access-list change were exercised on this one machine and account.

## Recommendation

**Go for use as a release candidate on your own machine(s), with two conditions:**

1. Run it as the service for a real day or two and look at the anomalies it raises (Checkpoint 4),
   changing `sensitivity` in the config if it is too noisy or too quiet.
2. Record the 24-hour overhead run (Checkpoint 5) and confirm the numbers stay within the targets.

**No-go for wider distribution** until those are done and there is an installer (or at least a
tested copy-and-install procedure) and a fresh-machine walkthrough. None of the open items is a known
defect; they are evidence not yet gathered.

## Decision

- [ ] Go as a release candidate (own machine), conditions above
- [ ] Go after: ______________________
- [ ] No-go: ______________________
