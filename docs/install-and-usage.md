# Install and usage guide

## Requirements

- Windows 10 or 11, 64-bit.
- The Rust toolchain (stable) to build it: <https://rustup.rs>. There is no installer yet; WinPerf
  runs from the `target\release` folder (or wherever you copy `winperf.exe`, `winperf-service.exe`
  and `winperf-report.exe`, keeping them together).
- Administrator rights are needed for only two things: installing the service, and per-process
  network attribution (see below). Everything else works as a normal user.

## Build

```powershell
cargo build --release
```

This produces three programs in `target\release`:

| Program | What it is |
|---|---|
| `winperf.exe` | The command-line tool and the terminal dashboard |
| `winperf-service.exe` | The Windows service host (installed for you by `winperf service install`) |
| `winperf-report.exe` | The browser report server |

If a command you expect says "unrecognized subcommand", the binary is older than the source:
rebuild with `cargo build --release`.

## First time

1. **Inventory.** `winperf inventory scan` lists installed applications. `winperf process list`
   lists running processes with their publisher and classification (Microsoft, third party,
   unsigned...). `winperf inventory exe <path>` shows the signature and version details of one file
   and why it was classified as it was.
2. **Look live.** `winperf tui` opens the terminal dashboard. Keys: `q` quit, arrows or `j`/`k`
   move, `←→` or Tab change the sort column (or click a header), Enter reverses it; `c`, `m`, `i`,
   `n`, `p`, `a` sort by CPU, memory, I/O, network, PID, name; `w` installed software, `h` history,
   `e` anomalies, `b` baselines, `s` settings.
3. **Record.** `winperf monitor run` samples every process (and the machine) every 5 seconds into
   the database until you press Ctrl+C. Only one recorder can write to a database at a time: the
   service and `monitor run` refuse to start if the other is recording.
4. **Learn.** Baselines are built from what has been recorded and refresh by themselves while the
   monitor runs. `winperf profile start` puts the monitor into *learning mode*: baselines are built
   but anomalies are held back, which is what you want for the first day or two on a machine.
   `winperf profile status` shows how far each baseline's confidence has got, and `winperf profile
   stop` ends learning mode. `winperf baseline update` recomputes now; `winperf baseline list`
   shows the stored baselines.
5. **Read the results.** `winperf anomalies list` and `winperf anomalies show <id>` for events;
   `winperf report` for a text summary of the last 24 hours; or open the browser report (below).

### Always-on monitoring: the service

From an **elevated** prompt:

```powershell
winperf service install      # installs, sets automatic (delayed) start, recovery actions, and starts it
winperf service status       # installed? running?
winperf service stop         # also: start
winperf service uninstall    # removes the service; the database and logs stay
```

The service runs as LocalSystem, starts at boot without anyone logged in, restarts itself after a
failure (after 5 s, 30 s, then 60 s) and writes its own log to
`C:\ProgramData\WinPerf\logs\service.log`. Because it runs as an administrator account it can also
attribute network use to processes. `winperf monitor status` (any prompt) tells you whether
something is recording, how fresh the data is and whether there are gaps.

The service does not start the browser report; run `winperf-report` when you want it.

### The browser report

```powershell
winperf-report                       # http://127.0.0.1:8099
winperf-report --port 9000 --db D:\data\winperf.db
```

It reads the same database, read-only, and never slows the recorder. Pick a time range (15 minutes
to 7 days, or custom) at the top. The dashboard shows the machine now, charts, the biggest users of
each resource (processes or applications) and active anomalies. Click a name for its page (metadata,
history with its baseline drawn as dashed lines, anomalies, runs); **Anomalies** lists events you
can filter by severity, resource and name, each with its explanation and the machine's state around
it. The **Download** section exports system history, anomalies and rankings as CSV or JSON.

To reach it from another machine, set `bind` and a `token` of at least 16 characters under
`[report]` in the config file; the page then needs `?token=...` once. There is no TLS, so only do
this on a network you trust.

## Commands at a glance

| Command | Purpose |
|---|---|
| `winperf inventory scan` / `inventory exe <path>` | Installed software; one file's signature and version |
| `winperf process list [--cmdline]` | Running processes (command lines are shown with secrets hidden) |
| `winperf system now` / `network now` | One-shot system health; per-process network (needs administrator) |
| `winperf monitor run` / `monitor status` | Record in the foreground; is something recording? |
| `winperf profile start\|stop\|status` | Learning mode and baseline confidence |
| `winperf baseline update\|list` | Recompute or show baselines |
| `winperf anomalies list\|show <id>` / `winperf report` | Events and the text summary |
| `winperf tui` | Terminal dashboard |
| `winperf service install\|start\|stop\|status\|uninstall` | The background service |
| `winperf maintain [--vacuum]` | Run the retention job now; optionally compact the file |
| `winperf config show\|path\|init` | The configuration |

Every command takes `--db <file>` and `--config <file>`; `inventory scan`, `process list` and some
others also take `--format json|csv` for machine-readable output.

## Configuration

`winperf config init` writes a commented `C:\ProgramData\WinPerf\config.toml`; `winperf config show`
prints what is in effect; `winperf config path` says where it is. A mistyped key is an error, not
silently ignored. The defaults:

| Section | Setting | Default | Meaning |
|---|---|---|---|
| `[monitor]` | `interval_secs` | 5 | Seconds between samples |
| | `signatures` | true | Verify executable signatures (the Microsoft / third-party split) |
| | `network` | true | Try to attribute network use to processes (needs administrator) |
| `[storage]` | `database` | `C:\ProgramData\WinPerf\winperf.db` | Where the data lives |
| `[retention]` | `raw_samples_days` | 2 | Raw 5-second samples |
| | `aggregate_1min_days` | 14 | 1-minute averages |
| | `aggregate_15min_days` | 180 | 15-minute averages |
| | `anomaly_days` | 180 | Resolved anomalies |
| `[detection]` | `sensitivity` | `normal` | `low`, `normal` or `high`; `cpu`, `memory`, `disk`, `network` can override it |
| `[baseline]` | `windows_hours` | `[1, 24, 168]` | Short, medium and long baseline windows |
| | `recompute_minutes` | 15 | How often the short window is refreshed (longer ones less often) |
| `[report]` | `bind`, `port`, `token` | `127.0.0.1`, 8099, none | Where the browser report listens |

`WINPERF_DB` and `WINPERF_CONFIG` environment variables override the database and config paths; a
`--db` or `--config` flag overrides those.

## Where things are

- Database: `C:\ProgramData\WinPerf\winperf.db` (plus `-wal` and `-shm` files while it is in use, and
  a `.lock` file while a recorder runs). The folder is restricted to SYSTEM, Administrators and the
  account that ran `monitor run`, `maintain` or `service install`.
- Service log: `C:\ProgramData\WinPerf\logs\service.log` (rotated at 5 MiB).
- Size: with the default retention expect a few GB at most, levelling off after about two weeks of
  recording. `winperf maintain --vacuum` gives freed space back to the disk (stop the recorder
  first).

## The first days

- Day 0: confidence is *insufficient* or *preliminary*; the monitor learns and detects little.
- Day 1 to 2: baselines become *established* for programs you use daily; use learning mode if you
  would rather not see early, uncertain events.
- A week: the 7-day window fills and weekday patterns are included. Expect to see some false alarms
  at first; if there are too many, set `sensitivity = "low"` in `[detection]` (or per resource), if
  you miss things, `high`.
- Anything flagged is only a statement that a program differs from its own history. Read the
  explanation on the anomaly page, and see [limitations.md](limitations.md).

## Uninstall

`winperf service uninstall` (elevated), then delete the folder you built in. The data in
`C:\ProgramData\WinPerf` stays until you delete it.
