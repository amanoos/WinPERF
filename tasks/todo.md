# WinPerf Task List

Sizes: XS 1 file, S 1-2, M 3-5. Verification for every task includes the Definition of Done (fmt, clippy -D warnings, `cargo test --workspace`). Plan and rationale: `tasks/plan.md`.

## Phase 0: Spike (de-risk before building)

- [x] **T1: Workspace skeleton + CI-less check script** (S)
  - AC: workspace with six crates compiling; `core` has no windows-rs dependency; `scripts/check.ps1` runs fmt/clippy/test.
  - Verify: `cargo build --workspace`, `scripts/check.ps1` passes.
  - Deps: none. Files: `Cargo.toml`, `crates/*/Cargo.toml`, `scripts/check.ps1`.
- [x] **T2: Spike: Windows API feasibility** (M). Findings in `documentation/spike-findings.md`. ETW network attribution works (admin); ETW per-process disk attribution did not (header PID invalid).
  - AC: throwaway binary proves: per-process CPU/mem/IO counters (`GetProcessTimes`, `GetProcessMemoryInfo`, `GetProcessIoCounters`), process start time, `WinVerifyTrust` on a Microsoft and an unsigned exe, ETW kernel disk and network events attributed to PID (note elevation needed), running as a service. Measure CPU/RAM overhead of each.
  - Verify: written findings in `documentation/spike-findings.md` stating per metric: API, accuracy, needs admin?, overhead, and a go/no-go for ETW.
  - Deps: T1. Files: `spikes/*`, `documentation/spike-findings.md`.
- [x] **T3: Spike: Tailwind CSS + ECharts static page via Axum** (S)
  - AC: Tailwind standalone CLI builds one vendored CSS file (no Node, no CDN); one Axum-served page renders a sample ECharts line chart styled with Tailwind, fully offline.
  - Verify: open in browser, DevTools shows zero external requests; record the build command in the findings doc.
  - Deps: T1.

### Checkpoint 0: Spike review
- [x] **Approved by human.** Findings doc reviewed. Decisions: ETW **network-only** in MVP (admin-only, optional); ETW disk attribution deferred to Phase 7; rusqlite vs SQLx still to confirm; report port default 8099. Update plan Open Questions.

## Phase 1: Inventory

- [x] **T4: Core domain types + process identity** (S)
  - AC: `ProcessKey{pid, start_time}`, `Classification`, `Metric<T>` with Available/Partial/Unavailable; unit tests prove PID reuse yields distinct keys.
  - Verify: `cargo test -p winperf-core`.
  - Deps: T1. Files: `core/src/{types,process}.rs`.
- [x] **T5: Installed software discovery (vertical: `winperf inventory scan` lists apps)** (M)
  - AC: reads HKLM 64/32-bit + HKCU Uninstall keys; captures FR-001 fields; dedupes the same product across hives; skips system components/updates entries with no DisplayName; tolerates missing values. CLI prints a table.
  - Verify: unit tests on a registry-reader trait with fixtures; manual: output compares to Settings > Installed apps within reason.
  - Deps: T4. Files: `windows/registry.rs`, `core/inventory/software.rs`, `cli/commands/inventory.rs`.
- [x] **T6: Executable metadata + signature classification** (M)
  - AC: **catalog-signed binaries (e.g. notepad.exe) must verify via CryptCATAdmin; file-mode WinVerifyTrust alone returns "no signature" for them (T2 finding)**; file version info, product/description/original filename; WinVerifyTrust result + signer subject; classification Microsoft Official / Third Party / Unsigned / Unknown driven *only* by a valid signature with Microsoft subject (name/path alone never yields Microsoft). Results cached by (path, mtime, size). No network revocation fetch.
  - Verify: tests: signed MS exe (e.g. `notepad.exe`) → Microsoft; a freshly compiled unsigned exe → Unsigned; a renamed fake `microsoft.exe` → not Microsoft; unreadable path → Unknown.
  - Deps: T4, T2. Files: `windows/signatures.rs`, `windows/version_info.rs`, `core/inventory/classify.rs`.
- [x] **T7: Running process inventory** (M)
  - AC: FR-003 fields; access-denied and exited-mid-scan processes are handled without panic and marked partial; process key per A2.
  - Verify: tests with a mock process source (exit mid-scan, access denied); manual: `winperf process list` matches Task Manager count ±churn.
  - Deps: T4, T6. Files: `windows/process_api.rs`, `core/processes/mod.rs`, `cli/commands/process.rs`.
- [x] **T8: Application grouping + JSON/CSV export** (M). Done with one gap: the product-name fallback (via version resources) is not implemented because process records don't carry version info; install-location and unique-publisher rules are.
  - AC: processes associated to installed apps by install-location/exe-path prefix, then publisher/product fallbacks; unmatched are grouped as "Unassociated (<publisher>)". `inventory scan --format json|csv`. Repeated scans are consistent.
  - Verify: unit tests for grouping (multi-process browser fixture); two consecutive scans give identical app list.
  - Deps: T5, T7. Files: `core/inventory/grouping.rs`, `cli/export.rs`.

### Checkpoint 1: Inventory complete
- [ ] PRD Phase 1 acceptance criteria all demonstrable; tests/clippy green; human reviews real inventory output for classification errors.

## Phase 2: Collection and Storage

- [x] **T9: SQLite storage foundation + migrations** (M). Done. The `executables` table doubles as the persistent signature cache (`cached_executable`), ready for T10's background classification.
  - AC: WAL, migrations runner, schema v1 for inventory/executables/processes (ProcessInstance with end time), configurable DB path in app-data dir; repository for inventory persisted by `inventory scan --save`.
  - Verify: tests on temp DB: migration idempotent; reopen survives; concurrent reader during write.
  - Deps: T8. Files: `storage/{db,migrations/0001.sql,repo/inventory.rs}`.
- [x] **T10: CPU + memory process collector → stored samples** (M). Done. The sampler does no signature checks (the "keep it off the sampling path" requirement is met by omission; background classification moved to T11). Live run: ~411 processes sampled per tick, 156 unreadable without admin, 50-70 ms per tick in a debug build.
  - AC: CPU% normalized by logical cores from cumulative time deltas (first sample = none, not 0); working set, private bytes, virtual, peak; `ResourceSamples` table; batched transactional inserts; `winperf monitor` (foreground, interval flag) records samples. **Signature verification must stay off the sampling path** (T7: a cold scan of 586 processes took 13.6 s with signatures vs 0.65 s without): sample first, classify in the background, and persist the signature cache (path, size, mtime -> result) in SQLite so restarts don't re-verify.
  - Verify: CPU-burner test process reads ~100%/cores ±tolerance; PID-reuse test creates two instances; DB row counts match.
  - Deps: T9. Files: `windows/metrics_api.rs`, `core/metrics/cpu.rs`, `storage/repo/samples.rs`.
- [x] **T11: Process lifecycle tracking, background classification + DB growth measurement** (M). Done; growth numbers are in `documentation/spike-findings.md` (~720 MB/day at 5 s, 5 GB per 7 days raw), which needs a retention decision at Checkpoint 2 / T34.
  - AC: instances opened on first sight (done in T10), `end_time` set when gone (the sampler already reports `gone`; the sink doesn't act on it yet); `last_seen` refreshed periodically (currently only set when first seen); engine survives access-denied/vanished processes; **background signature classification** (moved here from T10, whose monitor does no signature checks): a worker thread verifies newly seen executables off the sampling path, using the DB signature cache (`cached_executable`), and the engine thread (single writer) writes `executables` rows and links `process_instances.executable_id`; records rows/day and MB/day at 5s for this machine.
  - Verify: spawn/kill test process → start & end recorded; a new executable is classified without delaying ticks; numbers written to findings doc.
  - Deps: T10.
- [x] **T12: Disk I/O collector (process counters) + system metrics** (M). Done; live workload and broken-counter checks passed (see `documentation/spike-findings.md`). Sample rows now ~133 B (~0.95 GB/day at 5 s), which sharpens the open retention decision.
  - AC: read/write bytes and ops deltas from `GetProcessIoCounters` marked "process-level incl. non-disk I/O"; system CPU, memory/commit, physical disk util + queue (PDH), network throughput; `SystemSamples` table; unavailable counters recorded as such.
  - Verify: file-copy workload shows write rate; killing a PDH counter path leaves engine running with Unavailable.
  - Deps: T10. Files: `windows/{disk_api,pdh}.rs`, `core/system_health/`.
- [x] **T13: Configuration (TOML) + sampling engine** (M). Done. Retention, sensitivity and baseline-window settings are parsed and validated but not yet consumed (T19-T21, T34). Shutdown: a hard kill (not a real Ctrl+C) was tested live; Ctrl+C itself is covered by the stop-flag tests.
  - AC: config file/CLI with interval, retention, sensitivity, DB path; engine runs collectors on a tick via traits; drift-free interval; graceful shutdown flushes batches.
  - Verify: fake-clock tests; Ctrl+C leaves DB consistent.
  - Deps: T12. Files: `core/engine.rs`, `core/config.rs`.
- [x] **T14: Per-process network collector via ETW (network only)** (M). Done and verified elevated (99.98% attribution accuracy, TCP and UDP, session cleanup, no leaked sessions; see `documentation/spike-findings.md`). One item carried to the Checkpoint 2 soak run: the collector's own CPU cost at normal traffic (compare `--no-network` against attribution on).
  - AC: per T2 findings: ETW kernel session (TCP_IP **and UDP_IP** providers) behind a collector trait, PID from event payload; requires admin and falls back to Unavailable cleanly; handles another tool already holding the NT Kernel Logger; overhead measured. **Per-process disk via ETW is out of scope** (header PID invalid, see findings); disk stays "process I/O" counters plus system PDH.
  - Verify: download test attributes bytes to the right PID (TCP and a UDP/QUIC case); non-admin run reports Unavailable, no crash; CPU/RAM overhead recorded.
  - Deps: T13, T2. Files: `windows/etw.rs`.
- [x] **T15: TUI v1: System Overview + Process Explorer on live engine** (M). Done: state/sorting/selection and rendering are covered by 30 tests (incl. 80x24, `TestBackend`), and `winperf tui --snapshot` renders real live data. User tried it: "looks good, performance is decent". Follow-up from that trial: columns are now sortable by click on the header, ←/→ (Tab/BackTab) to move the sort column, Enter/Space to reverse; row click selects, wheel scrolls; `--no-mouse` disables mouse capture. Header hit areas are tested against the drawn headers. **Not machine-verified:** real mouse clicks and terminal restore after mouse capture (logic is tested with synthetic events; needs a person: click headers, quit, confirm the shell is normal).
  - AC: `winperf tui` shows system gauges, monitoring status, and a sortable process table (CPU/mem/disk/net/anomaly column placeholder); Unavailable metrics shown as "n/a"; usable at 80x24; quits cleanly restoring the terminal.
  - Verify: render tests via ratatui `TestBackend`; manual run.
  - Deps: T13. Files: `cli/tui/{mod,overview,processes}.rs`.

### Checkpoint 2: Monitoring MVP-core
- [x] (Signed off by the user; the Task Manager comparison was skipped by choice, so TUI numbers have not been checked by a human against Task Manager.) 1+ hour soak run: engine overhead <1% of one core and <100 MB RSS (record actuals), no crash, DB size consistent with T11. Human reviews TUI numbers against Task Manager.
  - Soak 1 (60 min, 5 s, 16 logical cores, `scripts/soak.ps1`): `--no-network` avg 1.82% of one core (median 1.53%), RSS 21 to 25 MB, DB 40.7 MB/hour (~0.98 GB/day, matches T11). Attribution on: avg 1.87%, RSS 28 MB. So **ETW costs only ~0.05 to 0.15 points**; the cost was the sampler. (The attribution run's 91.7 MB DB and 120 rows came from two instances sharing one output folder; not a valid growth figure.)
  - Profile: process observation was 49.5 ms/tick (one handle plus ~5 calls per process), observe_system 3.9 ms, Sampler 0.25 ms. Fix: one `NtQuerySystemInformation(SystemProcessInformation)` call for all processes (observe 15.5 ms; per-tick CPU 55.7 to 28.9 ms, ~0.58% of a core at 5 s). Side effect: protected processes are now measured too (0 unreadable, was ~150).
  - Soak 2 (new build, 60 min, 5 s, `--no-network`, signatures on): avg 1.47% of one core (median 1.09%, p95 1.46%); first 10 min avg 3.1% (signature backlog), **last 30 min avg 1.19%**; RSS 23 to 28 MB; DB 41.5 MB/hour. Better than soak 1 (1.82%) but **steady state is still above 1%**, and above the 0.58% the short `--no-signatures` run predicted. Unexplained gap (~0.6 points): candidates are the signature classifier still running, SQLite writes into a growing DB (WAL checkpoints), and the 100 ms sleep slices. Needs a phase breakdown inside the real `monitor run` (including the sink), not just observe.
  - Chase (controlled A/B at the real 5 s interval, 4 parallel runs on copies of the soak DB): **tick cost depends on DB size**, 24 ms/tick on a fresh DB vs 51 to 60 ms on a 41 MB one. Not the classifier (same with signatures off), not SQLite's page cache (16 MB cache: no change, reverted). Fixed one part: `last_seen` was rewritten for ~560 instances every tick, now every 60 ticks (`TOUCH_EVERY_TICKS`), about 15 ms/tick saved. **Root cause of the rest is write amplification:** measured disk writes are **3.1 MB/tick (~53 GB/day) on a populated DB, 0.28 MB/tick (4.8 GB/day) on a fresh one**, for ~1 GB/day of stored data. Each tick inserts ~560 rows that land on ~560 different pages of `ix_resource_samples_instance_ts (process_instance_id, ts_ms)`, and each dirty page is written to the WAL and again at checkpoint. Affects CPU and SSD wear. Needs a decision (index order, batching ticks per transaction, or both) before the schema freeze at Checkpoint 4.
  - Decision (user): batch 6 ticks. Done: `DbSink::with_flush_span` (monitor uses `DEFAULT_FLUSH_SPAN` = 30 s, ~6 ticks at 5 s; first tick of a run is written at once; engine calls the new `SampleSink::flush` when a run ends, so a clean stop loses nothing; a hard kill loses at most ~30 s). One transaction per flush. 4 new tests (six-at-a-time, flush on demand, engine flush at end of run, process that starts and ends inside one buffer). Measured, populated DB: CPU/tick ~55 to ~38 ms (two A/B rounds: 62.5 to 35.2 and 48.2 to 41.7, noisy); disk writes populated 53 to ~37 GB/day, fresh 4.8 to 1.1 GB/day. **Writes on a populated DB are still high** (~2.2 to 2.5 MB/tick); a bigger WAL checkpoint threshold did not help (reverted), and the cause of the remaining ~3,000+ page writes per flush is not understood. Next lever is the index order `(ts_ms, process_instance_id)` (needs a migration, before the Checkpoint 4 schema freeze).
  - Soak 3 (batching build, 60 min, 5 s, `--no-network`): avg 1.01% (median 0.65%, p95 0.88%), first 10 min 2.55% (signature backlog), **last 30 min avg 0.77%** (matches the 0.77% predicted from the short A/B); RSS 23 to 26 MB; DB 44.2 MB/hour.
  - Decision (user): reorder index. Done: migration `0005_samples_time_index` replaces both sample indexes with `(ts_ms, process_instance_id)`; 2 new tests (upgrade from v4 keeps rows and NULLs and swaps indexes; time-window query uses the new index). Measured on a populated DB (copy of the soak DB, upgraded by the migration): **disk writes 52.9 to 1.2 GB/day (0.07 MB/tick; fresh DB 0.05)**, **CPU/tick ~57 to ~19.5 ms** (two A/B rounds: 55.3 to 23.4, 58.6 to 15.6; ~0.39% of a core at 5 s). Tradeoffs recorded: `samples_for_instance` is now a full scan (needs a windowed variant for the report); retention must delete samples by time first and prune instances with foreign keys off (see T34).
  - Soak 4 (final build: batching + index reorder, 60 min, 5 s, `--no-network`): avg 0.89% (median 0.52%, p95 0.73%), first 10 min 2.47% (signature backlog; max 19.8% is that startup burst), **last 30 min avg 0.61%**; only 2 of 60 minutes above 1%; RSS 23 to 26 MB; DB 34.2 MB/hour (down from 44.2). The ~0.4% steady-state expected from the A/B was not reached; the measured ~0.6% includes the sampling cost of the soak itself and system noise. Both targets met (<1% of one core, <100 MB).
  - Soak 5 (final build, elevated, network attribution ON, 60 min, 5 s): avg 0.99% (median 0.65%, p95 0.78%), first 10 min 2.71%, **last 30 min avg 0.65%** (vs 0.61% without attribution: ~0.04 points); only 1 of 60 minutes above 1%; RSS 28.8 to 30.9 MB (about 6 MB more than without attribution); DB 51.7 MB/hour (network columns and more rows). Targets met with attribution on.
  - Not done: Task Manager comparison by a human (user signed off without it).

## Phase 3: Baselines

- [x] **T16: Baseline statistics module (pure)** (S). Done: `core/profiler/stats.rs` with `summarize` (count, min, peak, mean, median, unscaled MAD, sample stddev, interpolated p95; one buffer, one sort, MAD via selection; non-finite values skipped) and `growth_rate` (Theil-Sen slope; windows over 256 points are thinned evenly because the fit is quadratic). 11 tests (known answers, empty/NaN/single, spike robustness, order independence, proptest p95/median/mean within [min, peak]). `proptest` added as a dev-dependency of core. Full check passes.
  - AC: mean, median, MAD, stddev, p95, peak, growth rate (robust regression slope) over a window; handles empty/NaN/single-sample; no allocation per call beyond one sort.
  - Verify: table-driven unit tests with known answers + proptest for p95 within [min,max].
  - Deps: T4. Files: `core/profiler/stats.rs`.
- [ ] **T17: Baseline computation job + persistence (per executable and per application)** (M)
  - AC: windows 1h/24h/7d configurable; `BaselineProfiles` table for CPU/mem/growth/disk r/w/net rx/tx; recomputed on a schedule; per-process-instance vs application aggregation (sum across processes per tick).
  - Verify: seed DB with synthetic samples → expected baselines; rerun is idempotent.
  - Deps: T16, T11. Files: `core/profiler/baseline.rs`, `storage/repo/baselines.rs`, migration 0002.
- [ ] **T18: Baseline confidence + `profile start/stop/status` + TUI Baseline Explorer** (M)
  - AC: confidence levels from observation count and span (thresholds in config); `profile start|stop` toggles collection mode; Baseline Explorer shows averages/peaks/confidence/last update; insufficient data is clearly labelled.
  - Verify: unit tests on confidence boundaries; TestBackend render test.
  - Deps: T17, T15. Files: `core/profiler/confidence.rs`, `cli/commands/profile.rs`, `cli/tui/baselines.rs`.

### Checkpoint 3: Baselines
- [ ] After a multi-hour run, baselines look sane for known processes (e.g. browser, explorer) and "Insufficient" for new ones. Human spot-check.

## Phase 4: Anomaly Detection

- [ ] **T19: CPU anomaly detector (vertical: event stored + listed)** (M)
  - AC: fires only when (value > baseline-by-robust-z or ratio) AND > absolute floor AND sustained ≥ duration; sensitivity Low/Normal/High presets; suppressed when confidence is Insufficient; event has all FR-018 fields and a human-readable explanation; `winperf anomalies list`.
  - Verify: scenario tests: brief spike → no event; 0.5%→2% → no event; 8%→72% for 3 min → event; CPU burner end-to-end.
  - Deps: T17, T18. Files: `core/anomaly/{mod,cpu,rules}.rs`, `storage/repo/anomalies.rs`, migration 0003.
- [ ] **T20: Memory, memory-growth (potential leak), disk, network detectors** (M)
  - AC: reuse rule framework with per-resource thresholds; leak = sustained private-bytes slope with no reclamation over ≥ N min, worded "potential memory leak"; single step increase is not a leak.
  - Verify: scenario tests incl. sawtooth (GC) pattern → no leak; steady ramp → leak.
  - Deps: T19. Files: `core/anomaly/{memory,leak,disk,network}.rs`.
- [ ] **T21: System-pressure correlation + severity + lifecycle** (M)
  - AC: impact score from process share vs system CPU/mem/disk pressure; severity Informational/Warning/High/Critical per FR-018 definitions; active vs resolved events with duration; same condition updates one event instead of spamming.
  - Verify: same process at 15% CPU with idle vs saturated system → different severity; dedup test.
  - Deps: T20. Files: `core/anomaly/{pressure,severity,lifecycle}.rs`.
- [ ] **T22: Anomaly Explorer (TUI) + terminal notifications + `winperf report`** (M)
  - AC: active/history lists, sort/filter by severity; status bar badge on new anomaly; `winperf report` prints a text summary of top offenders for the last N hours.
  - Verify: TestBackend tests; manual with CPU burner.
  - Deps: T21. Files: `cli/tui/anomalies.rs`, `cli/commands/report.rs`.
- [ ] **T23: Remaining TUI screens: Inventory, System History, Configuration** (M)
  - AC: Inventory filter by class; History graphs for CPU/mem/disk/net with selectable range; Config edits persisted and applied.
  - Verify: TestBackend tests; config edit round-trips.
  - Deps: T15, T13.

### Checkpoint 4: Detection
- [ ] PRD Phase 4 acceptance met on synthetic and live scenarios. False-positive review over a real day of use: tune defaults. Human sign-off on sensitivity presets.

## Phase 5: Windows Service

- [ ] **T24: Service host (runs the shared engine, no TUI)** (M)
  - AC: `winperf-service` uses windows-service crate; SCM start/stop/pause states; runs engine with the same crate code path as foreground `monitor`; logs via tracing to file.
  - Verify: install manually with `sc create`, start/stop; samples written while no user is interactive.
  - Deps: T21. Files: `service/main.rs`, `windows/service.rs`.
- [ ] **T25: `service install/uninstall`, auto-start, recovery actions** (S)
  - AC: commands need and detect admin; delayed auto-start configurable; recovery restarts on failure; idempotent install/uninstall.
  - Verify: install → reboot test → running; kill process → restarts; uninstall leaves DB intact.
  - Deps: T24. Files: `cli/commands/service.rs`.
- [ ] **T26: Service/TUI coexistence + health + crash recovery** (M)
  - AC: TUI detects running service and becomes read-only viewer of the DB (never a second writer); `monitor status` reports last sample time, error counts, DB size; control path for `profile start/stop` is defined (config table polled by service); unclean shutdown leaves DB valid and open process instances closed on next start.
  - Verify: kill -9 the service mid-write → restart, integrity_check ok; TUI + service run together.
  - Deps: T25, T18.

### Checkpoint 5: Unattended
- [ ] 24 h unattended run via service; terminal closed throughout; data continuous; overhead targets hold.

## Phase 6: Browser Reporting

- [ ] **T27: Report service skeleton + read-only API (system, current, anomalies)** (M)
  - AC: Axum bound to 127.0.0.1 on a configurable port (default 8099; 8080 was occupied by svchost in T3), with a clear bind-failure error; read-only DB connection; JSON endpoints for system samples, active anomalies, status; non-localhost bind requires explicit config + token auth; no external requests.
  - Verify: API tests with temp DB; bind-address test; `curl` works, remote bind rejected without config.
  - Deps: T21. Files: `report/{main,api/*}.rs`.
- [ ] **T28: Dashboard page (health, utilization, top consumers, anomalies)** (M)
  - AC: Tailwind CSS layout (prebuilt vendored CSS); ECharts vendored; time range selector 15m/1h/6h/24h/7d/custom; polling refresh.
  - Verify: manual in browser; DevTools network tab shows zero external requests; loads <1s on 7d data.
  - Deps: T27, T3.
- [ ] **T29: Rankings (CPU, mem, disk r/w, net rx/tx; process vs application)** (M)
  - AC: six rankings with current/avg/peak over range; toggle process/app; SQL aggregates indexed; unavailable metrics shown as such.
  - Verify: API tests vs known seeded data; query time measured on a 7-day DB.
  - Deps: T28.
- [ ] **T30: Application detail + baseline-vs-actual charts** (M)
  - AC: metadata, publisher, processes, history charts, baseline band overlay read from stored baselines (no recomputation in the report crate), anomalies list, execution history.
  - Verify: seeded app renders all sections; baseline values equal DB rows exactly.
  - Deps: T29, T17.
- [ ] **T31: Anomaly investigation page** (M)
  - AC: filters severity/app/resource; shows detail with explanation text and concurrent system metrics (FR-027 example layout); timeline chart.
  - Verify: seeded anomalies filter correctly; explanation text matches stored description.
  - Deps: T30, T21.
- [ ] **T32: CSV/JSON export** (S)
  - AC: export rankings, history range, anomalies; large ranges streamed; command-line-injection-safe CSV (escape leading `=+-@`).
  - Verify: export round-trips; formula-injection test.
  - Deps: T31.
- [ ] **T33: Report/monitor non-interference check** (S)
  - AC: report queries do not block service writes (WAL, busy timeout, read-only); measured write latency with report under load.
  - Verify: load test with concurrent dashboard polling; sample cadence unaffected.
  - Deps: T32.

### Checkpoint 6: MVP (PRD §11)
- [ ] All 12 MVP items demonstrable end to end; human walkthrough of "computer is sluggish" workflow (PRD §9); decide on Phase 7 scope.

## Phase 7: Hardening

- [ ] **T34: Retention, aggregation (1-min, 15-min), pruning, VACUUM policy** (M)
  - AC: **decided retention (deviates from PRD 4.3): raw samples 2 days, 1-minute rollups 14 days, 15-minute rollups 180 days, anomalies 180 days** (already the config defaults; ~3.8 GB steady state vs ~9-10 GB at the PRD defaults); rollups preserve avg/max/p95 inputs (baselines for the 7-day window are computed from rollups, so keep enough to support them); reports select raw vs aggregate by range; pruning in small batches off the hot path; baselines and anomaly retention per defaults.
  - **Schema v5 constraint (from the Checkpoint 2 write-volume work):** `resource_samples` is indexed `(ts_ms, process_instance_id)` only, and `process_instance_id` is a foreign key with ON DELETE CASCADE, so deleting a `process_instances` row scans the whole samples table. Prune samples by time first, then prune instances with `PRAGMA foreign_keys = OFF` (in its own connection or transaction). Per-instance history needs a time window (`samples_for_instance` is a full scan; add a windowed variant for the report).
  - Verify: tests with accelerated time; DB size stabilizes in 3-day simulation.
  - Deps: T33.
- [ ] **T35: Security pass** (S)
  - AC: DB/dir ACL restricted to SYSTEM/Administrators/owner; command lines stored behind a config flag with secret-pattern redaction (`--password`, tokens); localhost binding verified; no outbound connections (verified with a netstat/ETW check); `cargo audit` clean.
  - Verify: inspect ACLs; test redaction patterns; run `cargo audit`.
  - Deps: T34.
- [ ] **T36: Performance validation + docs** (S)
  - AC: 24 h run with actual overhead numbers (CPU, RSS, DB size, writes/s) vs NFR-001; `README`, limitations doc (metric attribution caveats per 10.2), install/usage guide.
  - Verify: numbers recorded in docs; fresh-machine install walkthrough.
  - Deps: T35.

### Checkpoint 7: Release candidate
- [ ] All acceptance criteria met; human review and go/no-go.

## Parallelization

After Checkpoint 2, T16 (stats module) can start earlier, since it is pure and needs only T4. T23 (remaining TUI) can run alongside Phase 4. After T21, Phase 5 (service) and Phase 6 (report) are independent and can run in parallel, but both depend on the DB schema being frozen first, so freeze migrations 0001-0003 at Checkpoint 4.
