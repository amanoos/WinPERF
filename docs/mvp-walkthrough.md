# MVP walkthrough (Checkpoint 6)

Purpose: show each of the 12 MVP items from PRD section 11 working end to end on this machine, then
walk the "computer is sluggish" workflow from PRD section 9. Tick the box when you have seen it
work; write down anything that surprised you. Commands are run from the repository root after
`cargo build --release`; the examples use `.\target\release\winperf.exe` (written `winperf` below).

The walkthrough uses the default database (`%ProgramData%\WinPerf\winperf.db`). If you want a
clean slate, add `--db C:\temp\walk.db` to every command (and to `winperf-report`).

## Part 1: the 12 MVP items

| # | MVP item | Do this | You should see | Seen |
|---|---|---|---|---|
| 1 | Installed application inventory | `winperf inventory scan` | A list of installed programs with name, version, publisher and install location | [x] |
| 2 | Running process inventory | `winperf process list` | Running processes with PID, path and publisher | [x] |
| 3 | Microsoft vs third-party | Same two commands; also `winperf inventory exe "C:\Windows\System32\notepad.exe"` | A classification (Microsoft / third party / unknown) on each row; the exe command shows the signer and why | [x] |
| 4 | CPU monitoring | `winperf tui` (press `q` to leave) | Whole-machine CPU and a per-process CPU column that you can sort | [x] |
| 5 | Memory monitoring | Same dashboard | Memory in use, and per-process working set | [x] |
| 6 | Disk I/O | Same dashboard; `winperf system now` | Disk busy, throughput and per-process I/O | [x] |
| 7 | Network I/O | `winperf system now`; in an **elevated** prompt `winperf network now` | System network rates; with administrator rights, the processes using the network (without it, the tool says per-process network is unavailable) | [x] |
| 8 | Historical SQLite storage | `winperf monitor run` for a few minutes (Ctrl+C), then `winperf monitor status` | Sample counts and the database size growing; the file exists at the path shown | [ ] |
| 9 | Baseline generation | `winperf baseline update`, then `winperf baseline list` | A baseline (typical, p95, peak, confidence) per program | [x] |
| 10 | Statistical anomaly detection | `winperf anomalies list` and `winperf anomalies show <id>` | Detected events with severity, actual vs baseline, and the explanation text | [ ] |
| 11 | Ratatui terminal dashboard | `winperf tui` | System health header, sortable process table, anomaly view, settings | [x] |
| 12 | Basic browser reporting | `winperf-report` then open http://localhost:8099 | The dashboard (see Part 3) | [x] |

Notes for item 10: detection holds back while profiling mode is on (`winperf profile status`); a
fresh database has no baselines, so expect nothing until the monitor has run for a while. To see
events straight away, review the ones the monitor recorded during the earlier live run if you still
have that database.

## Part 2: first-time setup and always-on monitoring (PRD section 9)

1. `winperf inventory scan` (inventory), review the classifications.
2. `winperf profile start` (learn baselines), `winperf profile status` shows progress and confidence.
3. In an **elevated** prompt: `winperf service install`, then `winperf service start`;
   `winperf service status` should say running. (Installation changes the system, so I leave it to you.)
4. Wait. Confidence rises as data accumulates; `winperf profile stop` when you are satisfied, or leave
   it on for the first days.
5. `winperf monitor status` (from a normal prompt) shows the service recording: last sample age,
   samples in the last 24 h, gaps.

## Part 3: the "computer is sluggish" workflow (PRD section 9)

Do this while something is actually using the machine (for example run a CPU-heavy command in another
window for two minutes), or on the data already recorded.

1. Open the terminal dashboard (`winperf tui`) **or** the browser report (`winperf-report`, then
   http://localhost:8099; use the 15 min range). [ ]
2. Review current system utilization: the four "now" cards and the CPU, memory, disk and network charts. [ ]
3. Identify abnormal processes: "Top consumers right now", the **Biggest users** cards (try 1 h and
   24 h, and Processes vs Applications), and the **Active anomalies** card. [ ]
4. Compare against the baseline: click a ranked name to open its page; the dashed lines are its stored
   typical level and p95, with the shaded band between. Is the current behaviour outside the band? [ ]
5. Review duration and severity: **Anomalies** in the header; filter by severity or resource; open an
   event for its explanation, the baseline line and the system charts around it. [ ]
6. Decide which programs are putting the system under pressure: on the event page read "System
   pressure / this process's share" and the concurrent system CPU, memory and disk charts. [ ]
7. Download evidence: the Download section on the dashboard (CSV opens in a spreadsheet). [ ]

Questions to answer for the sign-off:

- Could you tell what was making the machine slow, and how long it had been going on?
- Was anything wrong or misleading (a number that looked off, a label you did not understand)?
- Which false positives did you see among the anomalies, and which real problem was missed?

## Known limits you will run into (so they are not a surprise)

- Per-process network needs administrator rights; the service has them, a normal prompt does not.
- 7-day charts and rankings are thin until the retention work (T34): raw samples are kept 2 days.
- Process disk figures count all I/O (files, pipes, devices), not only the physical disk.
- Memory is working set; memory shared between processes is counted in each.
- The report is a separate program (`winperf-report`); the service does not start it.
- Events stay "active" after the recorder stops until the next recorder start resolves them.
- The report has no TLS and listens on localhost only unless you configure a bind address and a token.
- A day of real use, the sensitivity sign-off (Checkpoint 4) and the 24 h unattended service run
  (Checkpoint 5) are still open.

## Phase 7 scope: your decision

Planned (see `tasks/todo.md`): T34 retention and rollups, T35 security pass (file permissions,
command-line redaction, `cargo audit`), T36 performance validation and docs (24 h overhead numbers,
README, install guide). Tell me what to add, drop or reorder; anything from the PRD's advanced
diagnostics (ETW disk attribution, for example) stays out unless you pull it in.

## Sign-off

- MVP items seen working: ___ / 12
- Sluggish-computer workflow usable: yes / no / with changes: ______________________
- Phase 7 scope: as planned / changes: ______________________
