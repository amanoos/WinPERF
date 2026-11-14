# Implementation Plan: WinPerf (Windows Process Performance Profiler & Anomaly Monitor)

Source: `WinPerf_PRD.md` v1.0. Greenfield: no code exists yet. Tasks are tracked in `tasks/todo.md`.

## Overview

A local-first Rust workspace that inventories Windows software and processes, samples per-process and system resource usage into SQLite, builds rolling statistical baselines, and flags sustained deviations that coincide with system pressure. It ships as a CLI/Ratatui TUI, a Windows service, and an Axum + browser report UI. One shared engine serves all three front ends.

## Architecture Decisions

| # | Decision | Rationale |
|---|---|---|
| A1 | Cargo workspace: `winperf-core` (pure logic, no Windows/UI deps), `winperf-windows` (all `unsafe`/windows-rs), `winperf-storage`, `winperf-cli` (clap + TUI), `winperf-service`, `winperf-report` | PRD NFR-005. Core takes collectors through traits, so baseline and anomaly logic is unit-testable with synthetic data and no Windows. |
| A2 | Process identity = `(pid, creation_time)` from day one | PRD 10.1. Retrofitting it later forces a schema migration. |
| A3 | Single writer (monitor engine), many readers, SQLite in WAL mode, batched transactional inserts | NFR-001/002; lets the TUI and report server read while the service writes. |
| A4 | **Recommend `rusqlite` over SQLx** | One writer and sync access. The engine's sampling loop doesn't need async DB. SQLx's compile-time macros and async add weight. PRD says "SQLx or rusqlite", so this is open for your override (see Q1). |
| A5 | Baseline/anomaly code is a pure function of stored samples plus config, living only in `winperf-core` | PRD 2.2.D: the report service must not reinterpret baselines. It only reads persisted baselines and anomalies. |
| A6 | Metric availability is first-class: each sample field is `Option`/flagged "unavailable / partial" | PRD 10.2, 5.2. Disk and network attribution may be partial without ETW. |
| A7 | Detection = absolute floor AND baseline deviation (robust: median/MAD) AND duration AND system pressure for severity | PRD 15.2, FR-015/017. |
| A8 | **Spike first (Phase 0)**: prove WinVerifyTrust, per-process I/O counters, ETW disk/network attribution, and service-without-session | PRD 15.3/15.4. ETW needs elevation, and its feasibility decides how real FR-007/008 can be. |
| A9 | Report UI is static HTML/JS served by Axum, bound to 127.0.0.1, styled with Tailwind CSS (prebuilt, vendored) and ECharts vendored locally (no CDN) | NFR-003 (no external transmission), offline operation. |

## Dependency Graph

```
Phase 0 spike (APIs, ETW, Tailwind build)
        │
workspace + core types (process identity, Option metrics)
        │
   ┌────┴────────────┐
 inventory      collectors (cpu/mem/io/sys)
   │                 │
   │            storage (schema, batch writer, lifecycle)
   │                 │
   │            sampling engine ──► TUI dashboard
   │                 │
   │            baseline engine (+ confidence)
   │                 │
   │            anomaly engine (+ pressure, leak, severity)
   │                 │
   │         ┌───────┴────────┐
   │     service (SCM)    report API ──► web UI
   └────────────┴────────────┘
              retention/aggregation, hardening, perf validation
```

## Phases

- **Phase 0: Technical spike.** Throwaway-quality `spikes/` binary. Output is a findings doc, no product code.
- **Phase 1: Inventory (PRD Phase 1).** Installed apps, processes, signatures, classification, app grouping, JSON/CSV export, simple TUI table.
- **Phase 2: Collection and storage (PRD Phase 2).** CPU/mem/disk/net/system collectors, SQLite, lifecycle, sampling loop, live TUI.
- **Phase 3: Baselines (PRD Phase 3).**
- **Phase 4: Anomalies (PRD Phase 4).**
- **Phase 5: Service (PRD Phase 5).** Placed after anomalies per the PRD. The shared engine means it is mostly wiring.
- **Phase 6: Web reporting (PRD Phase 6).**
- **Phase 7: Hardening and overhead validation.** Retention/aggregation, perf targets, security checks. Advanced diagnostics (PRD Phase 7) stays out of this plan.

Each vertical slice ends with something runnable. MVP (PRD §11) is reached at the end of Phase 6 (Checkpoint 6).

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Per-process network attribution is infeasible without ETW/elevation | High | Phase 0 spike (T2). Fall back to "unavailable" in the UI and docs (A6). Don't block MVP. |
| ETW overhead or complexity blows the NFR-001 budget (<1% CPU, <100 MB) | High | Spike measures it. ETW is a separate, optional collector behind a trait (T14). |
| Service (Session 0) can't read some processes or user details | Med | Treat access-denied as normal (FR-003). Test under a real service in T24. |
| WinVerifyTrust is slow and can block (revocation/network) | Med | Cache by (path, mtime, size). Offline policy flags (no revocation fetch). Run off the sampling thread. |
| SQLite growth at 5s × hundreds of processes (~100 rows/sample is ~1.7M rows/day) | Med | Batch inserts, only sample changed/active processes if needed, aggregation and pruning (T34). Measure DB size in T11. |
| Baselines flag legitimate bursts | Med | Floors, duration, confidence gating, median/MAD, sensitivity presets (T19–T21). |
| Tailwind needs a build step | Low | Use the Tailwind standalone CLI (no Node) to generate one CSS file that is committed/vendored. Verified in spike T3. |
| Single-writer assumption broken by TUI "profile start" while the service runs | Med | Define the control path in T26: TUI/CLI controls the service through a config table, never by a second writer. |

## Decisions made during build

- **Retention (decided, deviates from PRD 4.3):** raw samples 2 days (PRD: 7), 1-minute rollups 14 days (PRD: 30), 15-minute rollups 180 days, anomalies 180 days. Reason: measured ~0.95 GB/day of raw samples at 5 s (about 413 rows/tick x ~133 B), so the PRD defaults would settle near 9-10 GB; these settle near 3.8 GB. Rollups are built in T34; until then raw data simply accumulates. All values stay configurable.

## Open Questions (need human input)

1. ~~SQLx vs rusqlite~~ **Resolved:** `rusqlite` (A4 confirmed).
2. ~~Topcoat CSS~~ **Resolved:** Topcoat is legacy and dropped. The project uses Tailwind CSS (standalone CLI, output vendored, no CDN).
3. ~~Elevation~~ **Resolved:** service runs as LocalSystem. ETW is network-only in the MVP (optional, admin-only); ETW per-process disk attribution deferred to Phase 7 (see `documentation/spike-findings.md`). Report service default port is 8099. Catalog-signature verification is required in T6.
4. **Distribution**: MSI/installer in scope, or `winperf service install` only (PRD says the latter)? Assumed the latter.
5. **Windows toast notifications (FR-019 "optional")**: deferred past MVP. Confirm.
6. **Which Windows versions to test on**: assumed the dev machine (Win 11) only.

## Definition of Done (every task)

`cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` pass; new logic has tests; any `unsafe` is confined to `winperf-windows` with a safety comment.
