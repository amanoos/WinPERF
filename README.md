# WinPerf

A Windows performance profiler and anomaly monitor, written in Rust. It watches every process on
your machine, learns what is normal for each program, and tells you when something is not: a
program using ten times its usual CPU, memory that only ever grows, a slow machine and the program
behind it.

Everything stays on the machine. WinPerf makes no outside connections, keeps its data in a local
SQLite file that only administrators and you can read, and serves its browser report on
`127.0.0.1` by default.

## What it does

- **Inventory.** Lists installed applications and running processes, tells Microsoft software from
  third-party software (by signature), and ties processes to the application they belong to.
- **Monitoring.** Samples CPU, memory, disk and network for every process and for the machine, every
  5 seconds by default, into a SQLite database.
- **Baselines.** Builds a profile of normal behaviour for each program (typical level, 95th
  percentile, peak, growth) over 1 hour, 24 hours and 7 days, with a confidence level that grows as
  data accumulates.
- **Anomaly detection.** Flags sustained deviations from a program's own baseline and steadily
  growing memory, rates them by severity from how much the machine is under pressure, and explains
  each one in plain words.
- **Terminal dashboard** (`winperf tui`): live system health, a sortable process table, anomalies,
  baselines and settings.
- **Browser report** (`winperf-report`): dashboard, charts, "biggest users" rankings, application
  and anomaly pages with the baseline drawn on the charts, and CSV or JSON downloads.
- **Background service**: runs the monitor as a Windows service from boot, with crash recovery.
- **Retention.** Raw samples for 2 days, 1-minute averages for 14 days, 15-minute averages for 180
  days, so the database stops growing.

## Quick start

```powershell
cargo build --release
.\target\release\winperf inventory scan          # what is installed
.\target\release\winperf tui                     # live dashboard (q to quit)
.\target\release\winperf monitor run             # record samples (Ctrl+C to stop)
.\target\release\winperf-report                  # then open http://127.0.0.1:8099
```

For always-on monitoring install the service from an elevated prompt:

```powershell
.\target\release\winperf service install
```

The full guide, with every command, the configuration file and the first days of use, is in
[docs/install-and-usage.md](docs/install-and-usage.md). What the numbers can and cannot tell you is
in [docs/limitations.md](docs/limitations.md). What it costs to run (measured CPU, memory and
database growth) is in [docs/performance.md](docs/performance.md).

## Layout

| Crate | Role |
|---|---|
| `winperf-core` | Pure logic: types, statistics, baselines, anomaly rules, configuration, redaction |
| `winperf-windows` | The only crate with `unsafe`: Windows APIs, ETW, signatures, file permissions |
| `winperf-storage` | SQLite schema, migrations, samples, baselines, anomalies, rollups, retention |
| `winperf-runtime` | The recording run shared by the CLI and the service |
| `winperf-cli` | The `winperf` command and the terminal dashboard (Ratatui) |
| `winperf-service` | The Windows service host |
| `winperf-report` | The browser report (Axum, read-only over the database) |

`WinPerf_PRD.md` is the product requirements document; `tasks/` holds the plan and the checklist of
what has been built and verified; `docs/` holds the guides and the MVP walkthrough.

## Development

```powershell
.\scripts\check.ps1          # format check, clippy (warnings are errors), all tests
.\scripts\net-check.ps1      # confirms nothing leaves the machine
.\scripts\soak.ps1 -Minutes 60   # the recorder's own CPU, memory and database growth
```

The report's CSS is prebuilt and committed. After changing `crates/winperf-report/web/index.html`
or `app.js`, rebuild it with `crates/winperf-report/build-css.ps1` (needs the Tailwind standalone
CLI, see the script).
