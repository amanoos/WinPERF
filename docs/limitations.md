# What the numbers can and cannot tell you

WinPerf reports what Windows exposes about each process. Some of that is exact, some is a close
proxy, and some is not available at all. This page says which is which, so a figure on the screen
is not read as more than it is. (PRD section 10.2 asks for this: the system should say when a metric
is unavailable or only partly attributable.)

## Per-metric caveats

| Metric | What it is | Caveats |
|---|---|---|
| **CPU** | Share of the whole machine's CPU (all logical processors) used by the process, from the change in its kernel + user time between two samples | Exact over the sample interval. The first sample of a process has no value. Very short bursts between two samples average out. |
| **Memory** | The process's **working set** (physical memory currently held), and private bytes | Memory shared between processes (DLLs, mapped files) is counted in each process, so per-process figures can add up to more than the machine uses. Private bytes are the better leak signal; the working set is what the rankings use. |
| **Disk** | Per-process I/O read and write rates from the process I/O counters | These count **all** I/O the process does (files, pipes, devices, network), not only the physical disk, so a process can show "disk" activity without touching a disk. The *system* disk figures (busy %, queue, latency) are physical disks and exact. Per-process attribution to a specific physical disk is not done. |
| **Network** | Per-process bytes sent and received, from an event trace (ETW) | **Needs administrator rights** (the service has them; a normal prompt does not). When unavailable it is shown as "not measured", never as zero. Counts what the trace attributes to the process; traffic the kernel handles on a process's behalf may be missed or credited elsewhere. System-wide network rates are exact (physical adapters only). |
| **Anything protected** | Some system processes cannot be inspected | Their values show as unavailable (a `~` or dash), and they may have no application page. |

A value that was not measured is stored as missing (NULL) and shown as such. It is never silently
turned into zero, and charts leave a gap rather than drawing a flat line.

## Identity and classification

- A process is identified by its PID **and** start time, because Windows reuses PIDs. Processes are
  grouped by their executable file, and by installed application where the registry's install
  location lets WinPerf link them. Not every program registers itself as an installed application
  (portable programs, many developer tools), so an application ranking may list those by executable.
- **Microsoft vs third party** is decided from the code signature (including catalog-signed
  Windows files). "Unsigned" is not the same as malicious, and a valid signature is not a statement
  that software is safe or wanted.

## Baselines and anomalies

- **A program has no single "normal".** A browser or an IDE behaves differently when idle and when
  working. WinPerf keeps three windows (1 hour, 24 hours, 7 days) and a confidence level; an
  anomaly names the window and the confidence it was judged against. Early on, with little
  history, baselines are wide or missing, and you should expect both missed problems and false
  alarms until the 24-hour and 7-day windows have filled. Use learning mode (`profile start`) to
  hold anomalies back while that happens.
- **Detection is statistical and explainable, not magic.** An anomaly means "this program differs
  from its own recent history by more than the chosen sensitivity allows, for long enough". It does
  not know whether the cause is a fault, a big job you started, or an update. The sensitivity
  setting trades fewer, surer events against more, earlier ones.
- **Memory growth** is flagged from a steady rise in private bytes without reclamation. That is a
  *potential* leak, not proof: a program legitimately loading a large file looks the same.
- **Severity** comes from how much pressure the machine is under at the time and how much of it the
  program accounts for, not from how unusual the program is alone. A big deviation on an idle
  machine can rate lower than a small one on a machine out of memory.
- The 24-hour and 7-day baselines are computed from the 1-minute averages (the 7-day one has to,
  as raw samples only cover 2 days; the 24-hour one does it to keep the hourly recompute cheap), so
  they are slightly smoother than the 1-hour one, which uses the raw samples.

## History and resolution

- **Retention.** Raw 5-second samples are kept 2 days; older history is kept as 1-minute averages
  (14 days) and 15-minute averages (180 days). Ranges that reach back beyond the raw samples are
  drawn from averages, and the page says so. A short spike inside an averaging period is smoothed;
  **peaks from averages are the highest period average**, and in the rankings the sum of each
  process's period maximum (an upper bound of the true simultaneous peak).
- **Long ranges are sampled.** Rankings and application histories over a long range read an even
  subset of at most 1,500 to 2,000 time points, to stay fast. A program that ran for less than the
  gap between the points can be missing from that view; the page tells you the spacing.
- **Gaps are real.** If the monitor was not running (machine off, service stopped), there is no
  data for that time and charts show a gap. `winperf monitor status` reports gaps in the last day.
- Events still marked *active* after the recorder stopped stay active until the next recorder start
  resolves them.

## Overhead

WinPerf is meant to be light, not free: it samples every process every few seconds and writes to a
database. The measured figures, and how they were measured, are in
[performance.md](performance.md).

## Security and privacy

- Nothing leaves the machine; there are no outside connections (check it with
  `scripts\net-check.ps1`).
- The data folder is restricted to SYSTEM, Administrators and the account that set it up. A
  database you place in another folder is protected only by that folder's permissions.
- Command lines are **never stored**, and where shown they have passwords and tokens hidden. Process
  names and paths are stored and can themselves be sensitive.
- The browser report listens on `127.0.0.1` only unless you change it; any other address requires a
  token, and there is **no TLS**, so a token sent over a network is readable on the wire.
- WinPerf only observes. It never kills, throttles or changes any process.

## Not built

ETW-based per-process **disk** attribution to physical disks, GPU metrics, per-thread detail,
remote or multi-machine monitoring, alert delivery (email, chat), and an installer. These are out
of scope for this version (PRD section 1.4 and the Phase 7 advanced diagnostics).
