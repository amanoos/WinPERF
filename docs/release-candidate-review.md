# Release candidate review (Checkpoint 7)

Prepared 2026-11-15 for the go/no-go decision; updated 2026-11-17 after the 24-hour service runs and
the detection sign-off. This page says what has been shown to work, what has
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
| FR-014 to FR-018 detection, statistics, memory leaks, correlation, classification | Done | Signed off at Normal sensitivity after two days of the installed service (Checkpoint 4): 8 anomalies, all informational, and a deliberate CPU burn was caught. One known false positive (`dwm.exe` memory growth, see `docs/limitations.md`). |
| FR-019 notifications | Partly | Terminal notifications (line and bell), historical records, and the dashboard's active-anomaly card are done. The optional Windows notifications are not built. |
| FR-020, FR-021 terminal application and commands | Done | Ratatui dashboard with the views listed in the guide; full command set. |
| FR-022 to FR-027 browser report | Done | Dashboard, charts, rankings, application detail, anomaly pages. Deviations from the PRD wording: **Tailwind CSS instead of Topcoat** and default **port 8099 instead of 8080** (both decided earlier). |
| FR-028 export | Done | CSV and JSON for history, anomalies and rankings; formula-safe CSV. |
| Section 4 storage, 4.3 retention | Done | SQLite, migrations; retention is **deliberately shorter than the PRD's defaults** (raw 2 days, 1-minute rows 14 days, 15-minute rows 180 days) with rollups, to keep the file near 5 GB. |
| Section 5.3 service | Done | LocalSystem, delayed auto-start, recovery restarts, single-recorder lock. Install/uninstall verified by you in Phase 5; crash recovery tested. |
| NFR-001 performance | Met | 0.70 % of one core and 26 MB in the 12-minute soak; over 24 hours the installed service used about 32 MB (38 max) with flat handles. The first 24-hour run found an hourly write spike (0.5 to 2 GB), now fixed (about 190 MB); 546 MB an hour written overall. **Whole-day CPU of the final build was not measured** (earlier build 0.5 to 1.0 % of one core; 0.6 % in a 3-minute check of the final one). |
| NFR-002 reliability | Done | Two 24-hour unattended runs with no gaps; a force-killed service restarted by Windows with an 18-second gap; crash recovery and transactions tested. Reboot with nobody logged in not tested. |
| NFR-003 security | Done | Restricted data folder, no stored command lines (and redaction where shown), localhost by default, token required for other binds, no outside connections. No TLS. |
| NFR-004, NFR-005 | Done | Seven separated crates; the engine is independent of the front ends. |

## Open items

Closed since the first version of this page:

- **Checkpoint 4 (detection sensitivity): signed off at Normal.** Two days of the installed
  service: 8 anomalies, all informational; a replay of the rules over 48 hours gave 0 (low), 1
  (normal) and 16 (high) events; a deliberate CPU burn was raised with a correct explanation. One
  accepted false positive: `dwm.exe` memory growth (usage-driven, reclaimed hours later).
- **Checkpoint 5 (unattended): done.** Two 24-hour runs of the installed service with no gaps, and
  a force-killed service restarted by Windows (18-second gap). The first run found an hourly write
  spike (0.5 to 2 GB, growing with the database); it is fixed (about 190 MB).

Still open, none of them a known defect:

1. **Whole-day CPU of the final build: not measured.** Evidence: 0.5 to 1.0 % of one core for the
   earlier build over 24 hours, 0.6 % in a 3-minute check of the final one. Measure it yourself with
   `.\scripts\overhead.ps1 -Hours 24` if you want the number.
2. **Reboot with nobody logged in.** Not tested; the service is set to start automatically after a
   delay, so sampling before logon is expected but not seen.
3. **Fresh-machine install.** The guide was written from the commands, not tested on a clean
   machine. There is no installer: it is `cargo build` and copy.
4. **Checkpoint 1's note** ("human reviews real inventory output for classification errors"):
   walkthrough items 1 to 3 were ticked, which I take as that review; say if you want a closer pass
   at the classifications.
5. **Further write savings (optional).** The 7-day baseline could be read from the 15-minute
   rollups, removing most of the remaining 443 MB write every 7 hours.

## Known limitations that affect a go decision

(Full list in `docs/limitations.md`.)

- No TLS on the report; remote access is for trusted networks only.
- Peaks and averages from the older (rollup) history are smoothed.
- Long ranges are sampled for speed (the page says so).
- The service does not start the browser report; it is a separate program.
- A detection tuned on one machine will behave differently on another.
- The Windows service and the access-list change were exercised on this one machine and account.

## Recommendation

**Go for use as a release candidate on your own machine(s).** The two conditions in the first
version (a real day or two of anomalies, and the 24-hour overhead run) have been met, with the CPU
and reboot gaps listed above. Keep using it as the service and change `sensitivity` in the config if
it turns out too noisy or too quiet.

**No-go for wider distribution** until there is an installer (or at least a tested
copy-and-install procedure) and a fresh-machine walkthrough, and the reboot case has been seen. None
of the open items is a known defect; they are evidence not yet gathered.

## Decision

- [x] Go as a release candidate (own machine), conditions above (decided 2026-11-17; the open items
  above stay open, and wider distribution remains a no-go until they are closed)
- [ ] Go after: ______________________
- [ ] No-go: ______________________
