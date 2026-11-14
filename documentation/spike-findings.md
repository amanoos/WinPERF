# T2 Spike Findings: Windows API Feasibility

Spike crate: `spikes/winapi-spike` (standalone, throwaway). Machine: Windows 11, 16 logical CPUs, 595 processes, **non-elevated** shell. Run with `target\debug\winapi-spike.exe <procs|sign <path>|etw [s]|overhead [s]>`.

## Results

| Capability | API | Result (non-admin) | Notes / decision |
|---|---|---|---|
| Process list | `CreateToolhelp32Snapshot` | 595 processes | Works. Includes PID 0/4 pseudo-processes. |
| Per-process CPU, start time | `OpenProcess(LIMITED_INFORMATION)` + `GetProcessTimes` | 441 of 595 readable (**74%**) | 153 denied (System, Registry, smss, csrss, wininit, services...). Access-denied is normal, so FR-003/NFR-002 handling is mandatory. Elevation (service as SYSTEM) is expected to recover most; not yet measured. |
| CPU% | Delta of kernel+user 100ns times / (wall × logical CPUs) | Plausible vs Task Manager | First sample has no delta (must not be recorded as 0). Compare creation time to detect PID reuse (A2 confirmed workable). |
| Memory | `GetProcessMemoryInfo` (`PROCESS_MEMORY_COUNTERS_EX`) | Working set + `PrivateUsage` (private bytes) OK | Private *working set* is not in this struct; needs a different source (e.g. `QueryWorkingSet`/PDH). Defer to T10 and document if omitted. |
| Disk/other I/O | `GetProcessIoCounters` | Works | **Counts all I/O, not just disk**: e.g. `MSPCManagerCore.exe` shows 193,979 MB read lifetime (pipes/devices/network included). Present as "process I/O", never as physical disk. Matches PRD FR-007 caution. |
| Signatures | `WinVerifyTrust` (file mode) | **See below** | |
| Overhead | Full pass of all 595 procs (open+times+mem+io) | ~11 ms per pass; sampling at 5s ≈ **0.98% of one core ≈ 0.06% of all 16 cores**, 8 MB working set | Identical in debug and release: cost is syscalls. Measured with a naive loop. NFR-001 "<1% CPU" is satisfied if read as machine-wide; ambiguous if read per-core. Cheap optimisations: skip known-denied PIDs, avoid reopening handles. |
| ETW kernel trace (disk + TCP/IP) | `ferrisetw` `KernelTrace` | **Fails without admin**: `Access is denied (0x80070005)` | Confirms ETW needs elevation. Elevated attribution **not yet verified**, see "Open items". |

## Key finding: catalog-signed Windows binaries

`WinVerifyTrust` in file mode returns `0x800B0100` (no embedded signature) for `C:\Windows\System32\notepad.exe`, **the same code as an unsigned binary** (`winperf.exe`). `kernel32.dll` and `pwsh.exe` (embedded signatures) return 0.

Many core Windows binaries are catalog-signed. **T6 must fall back to catalog verification** (`CryptCATAdminAcquireContext2` / `CryptCATAdminCalcHashFromFileHandle2` / `CryptCATAdminEnumCatalogFromHash`, then `WinVerifyTrust` with `WINTRUST_CATALOG_INFO`). Otherwise most Microsoft processes would be misclassified as Unsigned, which would break FR-002. T6's tests should include notepad.exe specifically.

Also for T6:
- Verification latency: ~65–75 ms for signed files, ~4–9 ms for unsigned/missing. Caching by (path, mtime, size) is required, and it should run off the sampling thread.
- Used `WTD_REVOKE_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL` so no network access occurred.
- Signer *subject* extraction (needed to say "Microsoft") was **not** prototyped; plan for `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` (or `CryptQueryObject` for embedded signatures) in T6.

## ETW elevated run (user-run, 20 s, `winapi-spike etw 20`, admin PowerShell)

| Aspect | Result |
|---|---|
| Trace start | OK when elevated (fails with Access denied otherwise) |
| **Network, per process** | **Works.** `ferrisetw` kernel `TCP_IP` events, PID from the event's `PID` field and bytes from `size`, attributed plausibly: OneNote 148 KB, Docker Desktop 65 KB, chrome 32 KB, rider64 31 KB, Rider.BackendHost 29 KB, codex 17 KB, nordvpn-service 6 KB, claude 3 KB. |
| **Disk, per process** | **Does not work as written.** All 19,444 `DISK_IO` events (≈1.89 GB) carried header PID `0xFFFFFFFF`, so none was attributed. Kernel disk events complete in a system context; the issuing process must be recovered another way (map the event's issuing thread ID to a PID via thread/process start+rundown events, or use the file-I/O provider, which is *logical* I/O including cache hits, not physical). Not prototyped. |
| Gaps seen | Only TCP was counted. UDP (and therefore QUIC/HTTP3, e.g. Chrome) needs the `UDP_IP` provider too. Spike did not measure the trace's own CPU/RAM cost. The NT Kernel Logger is one system-wide session and may conflict with other tools that use it. |

**Conclusions**
- ETW **network** attribution is feasible as an optional, admin-only collector (add UDP).
- ETW **disk** per-process attribution is unproven and is more work than the PRD implies. Keep per-process disk as `GetProcessIoCounters` ("process I/O", labelled) plus system-level physical disk from PDH, and treat ETW disk attribution as PRD Phase 7 ("ETW-based process-level I/O attribution"), which is where the PRD already places it.

## Not yet verified (open items)

1. **Running as a Windows service (Session 0).** Not tested; covered by T24. The unreadable-process fraction under SYSTEM should be measured then.
2. **Physical disk util/queue and system network throughput (PDH).** Not probed; belongs in T12.
3. **ETW session overhead** (CPU/RAM) while tracing: measure in T14 before enabling by default.

## T3: Tailwind CSS + ECharts + Axum (offline page): PASS

Spike: `spikes/web-spike`. Verified in the in-app browser at `http://127.0.0.1:8099/`.

- **Offline, no CDN:** page made exactly 2 requests (`/app.css`, `/echarts.min.js`), both same-origin; 0 external. Assets are embedded in the binary with `include_str!`.
- **Tailwind:** standalone CLI `tailwindcss-windows-x64.exe` v4.3.5 (**111 MB**, git-ignored, build-time only; no Node). `vendor/tailwindcss.exe -i input.css -o static/app.css --minify` builds in ~100 ms to a **12 KB** CSS file. `input.css` is `@import "tailwindcss"; @source "./static/index.html";`. Product build must list every template path under `@source`, and the generated `app.css` should be committed so a normal `cargo build` needs no Tailwind.
- **ECharts:** 5.6.0 `echarts.min.js`, ~1.0 MB, vendored. Chart rendered correctly; resize handler works.
- **Axum 0.8 + tokio:** serves the page bound to `127.0.0.1` only (netstat confirms `127.0.0.1:8099`).
- **Port finding:** `0.0.0.0:8080` (the PRD's suggested port) is already in use on this machine by a Windows `svchost`. The report service must have a configurable port and report a clear error on bind failure; consider a different default (e.g. 8099) and update the PRD/T27 accordingly.
- **Binary size note:** embedding ECharts adds ~1 MB to the binary; fine.

## Recommendations for Checkpoint 0

- Proceed with CPU / memory / process I/O via the basic APIs. They are cheap and reliable for ~74% of processes without elevation.
- Treat process I/O as "process I/O", not physical disk; show physical disk only from system-level counters.
- **ETW in MVP for network only** (TCP + UDP), as an optional admin-only collector behind a trait (A8). **Per-process disk via ETW is out of the MVP** (deferred to PRD Phase 7).
- Add to T6: catalog-signature support is a hard requirement.

## T11: database growth and sampling cost (measured, release build)

Live run on this machine: `winperf monitor run --interval 5 --ticks 24` (2 minutes), ~413 processes sampled per tick, 153 unreadable without admin, signature classification running on a background thread.

| Measure | Result |
|---|---|
| Rows per sample | 1 per readable process per tick; avg **413 rows/tick** |
| Bytes per sample row | **~101 B** (whole file ÷ samples; includes two indexes) |
| Rows/day at 5 s | **~7.1 million** |
| Disk growth at 5 s | **~720 MB/day** |
| 7-day raw retention (PRD default) | **~5.0 GB** |
| Tick cost (release) | 37-73 ms steady state (first tick ~130-150 ms, which also describes every process); dominated by per-process syscalls, so release is barely faster than debug |
| Classification | 104 executables verified off-thread (59 Microsoft, 41 third party, 4 unsigned); all 423 instances linked; no tick was delayed by verification |
| Lifecycle | A short-lived child was opened, refreshed, and ended within one tick of exiting; 12 instances ended during the run; none sampled after ending |

**Implication.** Raw samples at the PRD defaults (5 s, 7 days) cost ~5 GB, which is large for a "lightweight" tool and will make the retention queries in T34 slow. This is the DB-growth risk from the plan, now quantified. Options for T34 / Checkpoint 2 (a decision for the owner, not yet taken):
1. Shorten raw retention (e.g. 24-48 h) and rely on 1-minute / 15-minute aggregates for history.
2. Store a sample only when a process's values changed meaningfully, or sample idle background processes less often.
3. Drop the standalone `ts_ms` index if the report queries don't need it (saves space and write cost).
4. Raise the default interval to 10-15 s (CPU % is an average over the interval, so little is lost).

The monitor's own CPU cost (~50 ms per 5 s ≈ 1% of one core ≈ 0.06% of this 16-core machine) is consistent with the T2 estimate; the formal NFR-001 check is the Checkpoint 2 soak run.

## T14: per-process network attribution via ETW (verified elevated, by the owner)

Run with `pwsh -File scripts\etw-check.ps1` from an elevated PowerShell on this machine.

| Check | Result |
|---|---|
| Loopback TCP transfer credited to the transferring PID | pass |
| Loopback UDP (QUIC-style) credited, send side near-exact | pass |
| `WindowsMetricsSource` turns the totals into a per-process rate within 0.5x-2x of the true rate | pass |
| Kernel session exists while running and is **gone after drop** (sessions otherwise outlive the process) | pass |
| A second collector in the same process fails cleanly and leaves the first counting | pass |
| Leftover `winperf` ETW sessions after the run | none |
| Non-admin fallback (`RequiresAdmin`, nothing stored as 0) | verified earlier from a normal shell; skipped here because the shell was elevated |

**Accuracy under load.** About 10 s of loopback TCP: 4,160 MB moved (~415 MB/s); ETW attributed 4,159 MB received and 4,159 MB sent to the process (**99.98%**). Working set grew by only 3.7 MB over the run.

**Overhead: partly answered.** The report's "15.2 s of CPU in 10 s wall" includes the traffic generator itself (several threads moving 415 MB/s), so it does **not** isolate what the ETW collector costs. What we know: memory growth is negligible, and at 415 MB/s of loopback (a rate far above normal desktop traffic) the callback kept up without losing bytes. The collector's CPU cost at ordinary traffic levels will be measured in the Checkpoint 2 soak run by comparing a monitor with `--no-network` against one with attribution on the same machine and workload. If the per-event schema parse proves costly, the callback can read the `PID` and `size` fields at fixed offsets from the raw event payload instead (both event groups put them first); not needed so far.

## T12: process I/O and system-wide metrics (measured)

**Sources.** System CPU: `GetSystemTimes` (kernel time includes idle). Memory and commit: `GetPerformanceInfo`. Physical disk (utilization, queue, read/write bytes, latency): PDH `\PhysicalDisk(_Total)\...` via `PdhAddEnglishCounterW` (English names work on any Windows language). Network: IP Helper `GetIfTable2`, **physical adapters only** (virtual/VPN/Hyper-V adapters would double-count); a newly appearing adapter contributes nothing until its second sighting so hot-plugging doesn't create a spike. Per-process I/O: `GetProcessIoCounters`, reported as `Partial` and stored in columns named `io_*` because it counts all I/O (files, pipes, devices, network), not just disk.

**Workload check.** A separate process wrote 2 GB (flushed to disk every 128 MB) while `monitor run --interval 1` sampled:

| | Idle baseline | During the write (4 ticks) |
|---|---|---|
| System disk write (PDH, physical) | ~1 MB/s | **385 - 638 MB/s** |
| Disk busy | ~2% | 15 - 21% |
| Disk latency | ~0.3 ms | 0.9 - 1.35 ms |
| Writer's process-I/O write rate | n/a (first sample) | **504 - 580 MB/s**, ~70 ops/s (the 8 MB writes), top writer by far |

The process and system views agree, and the writer's end was recorded.

**Broken counter.** With a bogus PDH path, only that metric is `Unavailable`; with all five disk counters bogus, CPU, memory, commit and network still report and the engine keeps running (live tests).

**Lesson learned while testing.** My first two attempts to generate the workload silently failed (`Start-Process` mangled a quoted script, so the child exited immediately and the "2 GB in 1.2 s" was bogus). The tool was fine; the check was wrong. Workloads for verification should be a script file run with `-File` and confirmed by their own side effects.

**Storage cost update.** The four process-I/O columns raise a sample row from ~101 B to **~133 B** (whole file ÷ rows). At 5 s: ~7.1M rows/day ≈ **0.95 GB/day**, ≈ **6.6 GB per 7 days** of raw samples. This sharpens the T11 retention decision (shorter raw retention, change-only storage for idle processes, or a longer default interval); still undecided. Nearly all process-I/O values are 0 for idle processes, and zeros are cheap in SQLite's record format, but the nullable REAL columns still add per-row header bytes.
