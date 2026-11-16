# Performance: what WinPerf costs

The targets (PRD NFR-001) are engineering goals to validate, not guarantees: idle CPU preferably
below 1%, average memory preferably below 100 MB, configurable sampling, no needless continuous
disk writes, efficient batched database writes.

## Measured on the development machine

16 logical cores, about 525 running processes, recording every 5 seconds (the default), release
build, no administrator rights (so no per-process network trace), measured with `scripts\soak.ps1`
(12 minutes of `winperf monitor run`, one reading a minute). Raw numbers: 12 minute rows below.

| Target | Result | Verdict |
|---|---|---|
| CPU, idle | **0.70 % of one core** on average after start-up (0.60 to 0.81 per minute), which is **0.04 % of the whole machine** | Under 1 % |
| Memory | **about 26 MB** working set (24.5 to 26.3 MB), flat over the run | Under 100 MB |
| Sampling | Every 5 s by default; `monitor.interval_secs` | Configurable |
| Disk writes | One transaction per tick (system sample plus every process's sample in one batch), WAL mode; about 4 MB written per 3 minutes (about 80 MB an hour, including the WAL) | Batched, no per-row commits |
| Database growth | About 0.7 MB a minute of raw samples (about 1 GB a day) on this machine | See sizing below |

Start-up is not idle: the first minute averaged **23 % of one core** while WinPerf checked the
signature of every running program's executable (a one-off, about 14 core-seconds; results are cached
in the database, so later starts are cheap). The maintenance job (rollups and pruning) first runs a
minute after start and is small after the first catch-up (see below).

Per minute (CPU % of one core, working set MB, database MB including WAL): 1: 23.38, 24.5, 1.0;
2: 0.60, 26.3, 2.4; 3: 0.75, 25.9, 2.8; 4: 0.73, 25.9, 3.6; 5: 0.68, 25.8, 4.3; 6: 0.65, 25.3, 5.2;
7: 0.60, 26.1, 6.0; 8: 0.81, 25.9, 6.7; 9: 0.62, 25.9, 7.2; 10: 0.68, 25.1, 8.0; 11: 0.73, 24.9, 8.9;
12: 0.81, 26.2, 9.6.

## Other measurements

- **The report does not slow the recorder** (T33): with four threads repeating the dashboard's
  heaviest requests against a 215 MiB database, the recorder's commit latency stayed at p50 1 ms,
  p99 5 ms, worst 11.5 ms (alone: 0.9 / 2.8 / 12 ms), against a 5000 ms tick.
- **Reports stay fast**: a 24-hour chart or ranking over millions of samples takes 0.4 to 0.6 s; a
  7-day chart from the rollups 0.09 s and 7-day rankings 0.16 s (T29, T30, T34).
- **Catch-up after upgrading** (T34): the first maintenance pass rolls up and prunes the raw
  samples; measured 10 s per 300 MiB of database (`winperf maintain` does it at once).

- **A long run found an hourly write spike, now fixed** (T36). A 24-hour run of the installed
  service (about 17 hours of usable rows; see the note in `tasks/todo.md`) showed the service at
  0.5 to 1.0 % of one core and about 33 MB, with flat handles and no gaps in the data. But once an
  hour, when the 24-hour baseline was recomputed from raw samples, it wrote 0.5 to 2 GB and used
  12 to 35 % of one core for about a minute, growing with the database (about 1.6 GB an hour in all).
  The sort spilled to temporary files. The 24-hour baseline is now computed from the 1-minute
  rollups once they are caught up. On a 1.6 GB copy of the real database the full baseline update
  went from 26 s and about 2.2 GB written to 4.9 s and about 0.33 GB.

## Sizing

Retention (2 days raw, 14 days of 1-minute rows, 180 days of 15-minute rows) bounds the file; it stops
growing once the oldest tier fills (about 6 months for the 15-minute rows, which are the smallest per
day). A rough estimate from the figures above, for a machine like this one (about 525 processes):
raw about 2 GB, 1-minute rows about 1.5 GB, 15-minute rows about 1.3 GB, so **roughly 5 GB at
steady state**; a machine with fewer processes needs proportionally less (the earlier estimate for
about 120 processes was 3.8 GB). Treat these as estimates until the long run below has been done.

## Not yet measured

- **A 24-hour run of the installed service.** Only 12 minutes were measured here. To record the real
  numbers (CPU, memory, handles, database growth and bytes written, a row a minute):

  ```powershell
  winperf service install            # elevated, if not already installed
  .\scripts\overhead.ps1 -Hours 24   # from any prompt, in a second window; writes %TEMP%\winperf-overhead.csv
  ```

  The summary (average, 95th percentile and maximum CPU; memory; database growth; MB written per
  hour) prints at the end and is saved next to the CSV. Compare it with the table above.
- Per-process network attribution (needs the service or an elevated prompt) adds an event trace;
  its cost has not been separated out.
- Behaviour on a machine with many more processes, or under heavy disk or CPU load of its own.
