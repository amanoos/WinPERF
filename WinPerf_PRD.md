# Product Requirements Document (PRD)
# Windows Process Performance Profiler & Anomaly Monitor

**Project Name:** Windows Performance Profiler (Working Name: WinPerf)  
**Version:** 1.0  
**Status:** Initial Requirements Draft  
**Target Platform:** Microsoft Windows 10/11 (64-bit)  
**Primary Language:** Rust  
**Terminal UI:** Ratatui  
**Web UI:** Topcoat CSS  
**Reporting Backend:** Rust  
**Database:** SQLite (initial recommendation)

---

# 1. Executive Summary

## 1.1 Product Overview

Windows Performance Profiler is a lightweight, locally operated monitoring and diagnostic application designed to identify programs and processes that exhibit abnormal resource consumption and contribute to declining computer performance.

The application will initially observe installed software and running processes, establish historical resource-consumption profiles, and continuously monitor deviations from those profiles.

The primary objective is to identify applications that behave differently from their established operating patterns, potentially explaining why a computer becomes sluggish, unresponsive, or experiences degraded performance.

The application will consist of three primary capabilities:

1. **System and Process Inventory:** Identify installed software, running processes, executable information, publishers, and Microsoft/non-Microsoft classifications.
2. **Baseline Profiling and Monitoring:** Collect resource statistics, establish normal operating profiles, and identify abnormal behavior.
3. **Performance Reporting:** Provide browser-accessible dashboards, historical charts, rankings, and diagnostic reports.

The system should initially target a single Windows workstation, with a modular architecture that permits future expansion.

## 1.2 Problem Statement

Windows computers can gradually become sluggish or unresponsive for numerous reasons, including:

- Applications consuming excessive CPU resources.
- Processes accumulating memory over time.
- Memory leaks.
- Excessive disk reads and writes.
- Background applications generating sustained disk activity.
- Excessive network traffic.
- Applications becoming stuck in repetitive processing loops.
- Background services consuming resources unexpectedly.
- Multiple applications competing for limited system resources.
- Applications behaving differently following updates.

Windows Task Manager provides a snapshot of current resource consumption but does not establish historical behavioral baselines for individual applications.

Consequently, identifying the application responsible for intermittent performance degradation can be difficult.

WinPerf addresses this problem by building historical behavioral profiles and identifying statistically significant deviations from normal operating conditions.

## 1.3 Product Goals

- Establish an inventory of installed and running applications.
- Distinguish Microsoft-published software from third-party software.
- Monitor individual processes and associate them with their parent applications.
- Establish normal resource-consumption baselines over time.
- Identify abnormal resource-consumption patterns.
- Correlate process-level anomalies with overall system performance.
- Provide historical and real-time performance visualization.
- Minimize the monitoring application's own resource footprint.
- Operate without requiring a cloud service or external account.
- Support unattended operation through a Windows background service.

## 1.4 Out of Scope

The initial release will not:

- Automatically terminate problematic processes.
- Automatically uninstall or disable applications.
- Modify Windows system configurations.
- Function as antivirus or malware-detection software.
- Perform automatic application optimization.
- Upload monitoring data to an external service.
- Monitor other computers remotely.
- Attempt to determine whether an application is malicious solely from resource-consumption behavior.

The product is a performance diagnostic tool, not a security or remediation product.

---

# 2. System Architecture

## 2.1 Architectural Overview

The system should be divided into independent modules with clearly defined interfaces.

The monitoring engine must not depend on Ratatui or the browser reporting interface.

Proposed architecture:

```text
    +---------------------------------------------+
    |              Windows Operating System       |
    |                                             |
    |  Installed Software | Running Processes    |
    |  CPU | Memory | Disk I/O | Network I/O      |
    +----------------------+----------------------+
                           |
                           v
    +---------------------------------------------+
    |             WinPerf Core Engine             |
    |                                             |
    |  1. System Inventory                        |
    |  2. Process Discovery                       |
    |  3. Resource Collection                     |
    |  4. Baseline Profiler                       |
    |  5. Anomaly Detection                       |
    |  6. System Health Correlation               |
    +----------------------+----------------------+
                           |
                           v
    +---------------------------------------------+
    |              Data Persistence               |
    |                                             |
    |  SQLite Database                            |
    |  Historical Samples                         |
    |  Baselines                                  |
    |  Anomaly Events                             |
    |  Inventory                                  |
    +----------------------+----------------------+
                           |
              +------------+------------+
              |                         |
              v                         v
    +----------------------+  +----------------------+
    | Terminal Application |  | Reporting Service    |
    |                      |  |                      |
    | Rust + Ratatui       |  | Rust Web Backend     |
    | Interactive Monitor  |  | HTTP API             |
    | System Overview      |  | Topcoat CSS UI       |
    | Process Rankings     |  | Performance Charts   |
    +----------------------+  +----------------------+
```

## 2.2 Architectural Components

### A. WinPerf Core Engine

The core engine implements all monitoring and profiling functionality.

Responsibilities:

- Discover installed applications.
- Enumerate running processes.
- Collect resource statistics.
- Calculate baseline profiles.
- Evaluate deviations from baselines.
- Generate anomaly events.
- Persist collected information.
- Calculate overall system performance indicators.

This component must be independent of any user interface.

### B. Terminal Application

A Rust command-line application using Ratatui.

Responsibilities:

- Initial configuration.
- Inventory management.
- Starting and stopping profiling.
- Displaying live system statistics.
- Displaying running processes and resource consumption.
- Viewing anomalies.
- Displaying monitoring status.
- Providing diagnostic commands.

### C. Monitoring Service

A Windows background service responsible for continuous monitoring.

It should be possible to install, start, stop, and configure the service independently of the terminal application.

Responsibilities:

- Run automatically during Windows startup, subject to configuration.
- Perform scheduled process discovery.
- Collect resource statistics.
- Evaluate anomalies.
- Persist monitoring data.
- Maintain monitoring health information.

### D. Reporting Service

A browser-accessible reporting application.

Recommended implementation:

- Rust backend using Axum.
- HTTP/JSON API.
- Topcoat CSS for presentation.
- JavaScript charting library for interactive charts.
- SQLite access through a shared data-access module.

The reporting service should initially access the same local database used by the monitoring engine.

It must not duplicate or independently reinterpret the baseline calculations.

---

# 3. Functional Requirements

## 3.1 System Inventory

### FR-001: Installed Software Discovery

The application shall enumerate installed Windows applications.

Information should be collected from:

- Windows uninstall registry entries.
- 64-bit application registry entries.
- 32-bit application registry entries.
- Per-user application registry entries.
- Other relevant Windows installation metadata.

Information collected should include:

| Attribute | Description |
|---|---|
| Application Name | Installed program name |
| Publisher | Software publisher |
| Version | Installed version |
| Install Date | Installation date, when available |
| Install Location | Application installation directory |
| Uninstall Command | Registered uninstall command, when available |
| Registry Source | Registry location where discovered |
| Classification | Microsoft / Third Party / Unknown |

The application should avoid treating individual executable processes as separate installed applications when they belong to the same product.

### FR-002: Microsoft and Third-Party Classification

The application shall classify installed programs and running executables.

Proposed classification:

- Microsoft Official: Valid Microsoft Authenticode signature.
- Third Party Official: Valid digital signature from another publisher.
- Unsigned: No valid digital signature.
- Unknown: Publisher or signature cannot be established.

Additional metadata should be collected:

- Digital signature publisher.
- Signature validity.
- Certificate information, when available.
- File description.
- Product name.
- Original filename.
- Executable path.

Important: Microsoft signature verification should be used as the primary indicator of Microsoft publisher identity. File names, installation paths, and product names alone must not establish that a program is an official Microsoft application.

The system should distinguish publisher identity from product ownership and Windows component classification.

### FR-003: Running Process Inventory

The application shall enumerate all accessible running processes.

Collected information:

| Attribute | Description |
|---|---|
| PID | Process ID |
| Parent PID | Parent process ID |
| Process Name | Executable name |
| Executable Path | Full executable path |
| Publisher | Digital signature publisher |
| Classification | Microsoft / Third Party / Unsigned / Unknown |
| Start Time | Process start timestamp |
| User Account | Associated Windows account |
| Session ID | Windows session identifier |
| Command Line | Process command line, where accessible |
| Application Group | Associated installed application |

The application must handle processes that terminate during enumeration and processes for which Windows denies access.

### FR-004: Application-to-Process Association

The application should associate individual processes with their parent applications.

For example, a browser application may have multiple processes for:

- Main application.
- Tabs.
- Extensions.
- GPU rendering.
- Background tasks.

The system should support both individual process analysis and aggregated application-level analysis.

---

## 3.2 Resource Monitoring

### FR-005: CPU Monitoring

Collect CPU statistics for each process.

Required metrics:

- CPU utilization percentage.
- CPU time consumed.
- Average CPU utilization.
- Peak CPU utilization.
- CPU utilization over configurable intervals.

System-level metrics:

- Total CPU utilization.
- CPU utilization by logical processor, where practical.
- System idle percentage.

CPU measurements should be normalized consistently across processors and logical cores.

### FR-006: Memory Monitoring

Collect the following process-level metrics:

- Working Set.
- Private Working Set, where available.
- Private Bytes.
- Virtual Memory Size.
- Peak Working Set.
- Memory utilization percentage.
- Memory growth over time.

System-level metrics:

- Total physical memory.
- Available physical memory.
- Committed memory.
- Commit limit.
- Memory pressure indicators.
- Paging activity, where available.

The system should distinguish between memory allocated by a process and physical memory currently resident in RAM.

### FR-007: Disk I/O Monitoring

Collect:

- Read bytes per second.
- Write bytes per second.
- Total bytes read.
- Total bytes written.
- Read operations per second.
- Write operations per second.
- I/O operation counts.
- I/O response or latency indicators where reliable attribution is available.

The application should distinguish between process-level I/O activity and actual physical disk activity.

Where possible, collect physical disk utilization and queue information to correlate process activity with system-level disk bottlenecks.

### FR-008: Network I/O Monitoring

Collect:

- Bytes received per second.
- Bytes transmitted per second.
- Total bytes received.
- Total bytes transmitted.
- Network activity over time.

Where technically possible, associate network activity with individual processes.

The implementation should account for limitations of ordinary Windows network statistics and use suitable Windows networking or event-tracing interfaces for process attribution.

### FR-009: System-Wide Performance Monitoring

Process statistics alone are insufficient to determine whether a computer is becoming sluggish.

The application shall monitor overall system health.

Metrics should include:

- Total CPU utilization.
- Available memory.
- Memory commit utilization.
- Physical disk utilization.
- Disk queue length.
- Disk latency, where available.
- Network throughput.
- System responsiveness indicators, where feasible.

The system should be able to correlate individual process activity with overall system degradation.

---

## 3.3 Baseline Profiling

### FR-010: Baseline Collection Mode

The application shall provide an initial profiling mode.

During this mode, the monitoring engine collects resource-consumption statistics for running applications and processes.

The objective is to establish the normal operating characteristics of each application.

The profiling process should support:

- Configurable sampling intervals.
- Continuous collection.
- Historical data retention.
- Automatic process discovery.
- Application grouping.
- Baseline calculation.

Suggested initial sampling interval: 5 seconds.

The sampling interval must be configurable.

### FR-011: Baseline Profiles

The system shall maintain baseline profiles for individual processes and aggregated applications.

Baseline information should include:

| Metric | Baseline Data |
|---|---|
| CPU | Average, median, 95th percentile, peak |
| Memory | Average, median, 95th percentile, peak |
| Memory Growth | Typical growth rate |
| Disk Read | Average and peak throughput |
| Disk Write | Average and peak throughput |
| Network Receive | Average and peak throughput |
| Network Transmit | Average and peak throughput |

Baselines should be calculated using rolling historical windows.

Recommended initial baseline windows:

- Short-term: 1 hour.
- Medium-term: 24 hours.
- Long-term: 7 days.

The application should support configurable baseline windows.

### FR-012: Baseline Segmentation

Resource consumption varies according to application activity.

For example:

- A browser consumes different resources when idle versus loading multiple pages.
- Antivirus software may periodically perform intensive scans.
- Windows Update may temporarily consume substantial CPU and disk resources.
- Backup applications may exhibit scheduled high disk utilization.

The application should eventually support contextual baseline profiles based on:

- Time of day.
- Day of week.
- Process uptime.
- Application activity level.
- Application operating state.

For the initial release, basic rolling baselines are sufficient.

### FR-013: Baseline Confidence

A baseline should not be treated as reliable until sufficient historical observations have been collected.

The system should maintain:

- Number of observations.
- Baseline creation date.
- Last updated date.
- Observation period.
- Confidence level.

Suggested confidence levels:

- Insufficient Data.
- Preliminary.
- Established.
- High Confidence.

Anomaly detection should account for baseline confidence.

---

## 3.4 Anomaly Detection

### FR-014: Resource Deviation Detection

The application shall continuously compare current process behavior against established baselines.

The anomaly detection engine should identify:

- Unusually high CPU consumption.
- Unusual memory consumption.
- Abnormal memory growth.
- Excessive disk reads.
- Excessive disk writes.
- Unusual network activity.
- Significant deviations across multiple resource categories.

The system should distinguish between temporary spikes and sustained abnormal behavior.

### FR-015: Statistical Anomaly Detection

The initial implementation should use explainable statistical techniques rather than machine learning.

Recommended techniques:

- Moving averages.
- Standard deviation.
- Median and median absolute deviation (MAD).
- Percentile-based thresholds.
- Rate-of-change detection.
- Sustained threshold violations.

An example detection rule:

A process is considered anomalous when its CPU utilization:

1. Exceeds its established baseline by a configurable threshold.
2. Exceeds an absolute minimum utilization.
3. Remains elevated for a configurable duration.

The system should support configurable sensitivity levels.

Suggested initial sensitivity configuration:

- Low: More conservative anomaly detection.
- Normal: Balanced detection.
- High: More aggressive detection.

Thresholds should be configurable independently for CPU, memory, disk, and network.

### FR-016: Memory Leak Detection

The application should identify potential memory leaks.

Detection should consider:

- Sustained private memory growth.
- Growth rate over time.
- Memory usage relative to baseline.
- Lack of memory reclamation during extended operation.

A single increase in memory consumption must not be classified as a memory leak.

The resulting event should be described as a potential memory leak, not a confirmed leak.

### FR-017: System Performance Correlation

An important requirement is identifying which processes are contributing to overall system degradation.

The system should correlate:

- Process CPU consumption with total CPU utilization.
- Process memory consumption with available physical memory.
- Process disk I/O with physical disk utilization.
- Process network activity with overall network throughput.

The system should calculate a process-level impact assessment.

For example:

A process consuming 15% CPU may not be problematic when the system is otherwise idle. However, a process consuming 15% CPU while the CPU is already saturated could contribute to noticeable performance degradation.

The anomaly engine should consider both individual resource deviation and system-level resource pressure.

### FR-018: Anomaly Classification

Detected anomalies should be categorized.

| Severity | Description |
|---|---|
| Informational | Unusual activity without measurable system impact |
| Warning | Significant deviation from baseline |
| High | Sustained deviation associated with system resource pressure |
| Critical | Severe resource consumption associated with substantial system degradation |

Each anomaly event should contain:

- Process ID.
- Application name.
- Executable path.
- Resource category.
- Current measurement.
- Baseline measurement.
- Deviation percentage.
- Duration.
- System health indicators.
- Detection timestamp.
- Severity.
- Explanation of why the event was generated.

### FR-019: Anomaly Notifications

The application should provide:

- Terminal notifications.
- Historical anomaly records.
- Browser dashboard notifications.
- Optional Windows notifications.

Automatic process termination or remediation is explicitly excluded from the initial release.

---

## 3.5 Terminal Application

### FR-020: Terminal Interface

The application shall provide a terminal interface implemented using Rust and Ratatui.

The interface should be optimized for interactive monitoring and diagnostic operations.

Suggested screens:

#### A. System Overview

Display:

- Overall CPU utilization.
- Memory utilization.
- Disk activity.
- Network activity.
- Monitoring status.
- Baseline profiling status.
- Number of running processes.
- Number of detected anomalies.

#### B. Process Explorer

Display a sortable table containing:

- Process name.
- PID.
- Publisher.
- CPU percentage.
- Memory consumption.
- Disk I/O.
- Network I/O.
- Anomaly status.

Allow sorting by resource consumption.

#### C. Application Inventory

Display:

- Installed applications.
- Running applications.
- Microsoft applications.
- Third-party applications.
- Unsigned applications.
- Unknown publishers.

#### D. Baseline Explorer

Display:

- Application baseline status.
- Historical resource averages.
- Peak resource consumption.
- Baseline confidence.
- Last baseline update.

#### E. Anomaly Explorer

Display:

- Active anomalies.
- Historical anomalies.
- Severity.
- Resource category.
- Application responsible.
- Deviation from baseline.

#### F. System History

Display terminal-based time-series graphs for:

- CPU.
- Memory.
- Disk I/O.
- Network I/O.

#### G. Configuration

Allow configuration of:

- Sampling interval.
- Baseline windows.
- Detection sensitivity.
- Data retention.
- Monitoring mode.
- Service configuration.

### FR-021: Command-Line Operations

The application should support non-interactive commands.

Proposed command structure:

```bash
winperf inventory scan

winperf profile start

winperf profile stop

winperf monitor start

winperf monitor stop

winperf monitor status

winperf process list

winperf anomalies list

winperf service install

winperf service uninstall

winperf report
```

Interactive Ratatui mode should be available through:

```bash
winperf tui
```

---

## 3.6 Browser Reporting Service

### FR-022: Web Reporting Interface

The application shall provide a browser-based reporting interface.

Recommended implementation:

- Rust.
- Axum.
- Topcoat CSS.
- JavaScript charting library.
- JSON-based API.
- SQLite database.

The reporting service should be independently executable.

Suggested initial URL:

```text
http://localhost:8080
```

The service should be accessible only from localhost by default.

Remote access should require explicit configuration and appropriate authentication.

### FR-023: Reporting Dashboard

The primary dashboard should display:

- Current system health.
- Current resource utilization.
- Top resource-consuming applications.
- Active anomalies.
- Historical performance trends.
- Monitoring status.

### FR-024: Resource Consumption Rankings

The reporting interface shall provide separate rankings for:

1. Highest CPU consumers.
2. Highest memory consumers.
3. Highest disk read consumers.
4. Highest disk write consumers.
5. Highest network receive consumers.
6. Highest network transmit consumers.

Each ranking should support:

- Current consumption.
- Average consumption.
- Peak consumption.
- Historical consumption.
- Configurable time range.

The interface should support both process-level and application-level rankings.

### FR-025: Performance Charts

The reporting interface should provide interactive charts.

Required charts:

- CPU utilization over time.
- Memory utilization over time.
- Disk read/write throughput.
- Network receive/transmit throughput.
- Individual application resource consumption.
- System-wide resource consumption.
- Baseline versus actual resource consumption.
- Anomaly event timeline.

Users should be able to select:

- Last 15 minutes.
- Last hour.
- Last 6 hours.
- Last 24 hours.
- Last 7 days.
- Custom date range.

### FR-026: Application Detail Report

Selecting an application should display its detailed performance profile.

Information should include:

- Application metadata.
- Publisher information.
- Associated processes.
- CPU consumption history.
- Memory consumption history.
- Disk I/O history.
- Network I/O history.
- Established baseline.
- Historical peaks.
- Detected anomalies.
- Process execution history.

### FR-027: Anomaly Reports

The reporting interface should provide a dedicated anomaly investigation page.

The user should be able to:

- View active anomalies.
- Filter by severity.
- Filter by application.
- Filter by resource type.
- Review historical events.
- Compare actual consumption with baseline.
- Identify concurrent system performance degradation.

The interface should explain the detection reason in understandable terms.

Example:

```text
Application: ExampleApp.exe

CPU Consumption:       72%
Established Baseline:  8%
Deviation:             9x baseline
Duration:              3 minutes

System CPU Utilization: 96%

Assessment:
Sustained CPU consumption significantly exceeds
the established baseline and coincides with
elevated system CPU utilization.
```

### FR-028: Data Export

The reporting service should eventually support:

- CSV exports.
- JSON exports.
- Historical performance reports.
- Anomaly reports.

---

# 4. Data Architecture

## 4.1 Database

SQLite is recommended for the initial implementation.

Reasons:

- No separate database server required.
- Lightweight.
- Suitable for a single-workstation application.
- Native Rust ecosystem support.
- Easy deployment and backup.
- Supports concurrent readers and a controlled writer architecture.

Recommended Rust libraries:

- SQLx or rusqlite.
- Serde.
- Tokio.

The database should be stored in a configurable local application-data directory.

## 4.2 Proposed Data Entities

### InstalledApplications

- ApplicationId
- Name
- Publisher
- Version
- InstallLocation
- InstallDate
- Classification
- DiscoveryTimestamp

### Executables

- ExecutableId
- FilePath
- FileName
- ProductName
- FileDescription
- Publisher
- SignatureStatus
- FileVersion
- FileHash

### Processes

- ProcessInstanceId
- PID
- ParentPID
- ExecutableId
- ApplicationId
- StartTimestamp
- EndTimestamp
- UserAccount
- SessionId

A process instance must be distinguished from its PID because Windows can reuse process IDs.

### ResourceSamples

- SampleId
- ProcessInstanceId
- Timestamp
- CPUPercentage
- WorkingSetBytes
- PrivateBytes
- DiskReadBytes
- DiskWriteBytes
- DiskReadOperations
- DiskWriteOperations
- NetworkReceivedBytes
- NetworkSentBytes

### SystemSamples

- SampleId
- Timestamp
- TotalCPU
- AvailableMemory
- CommittedMemory
- DiskUtilization
- DiskQueueLength
- NetworkThroughput

### BaselineProfiles

- BaselineId
- ExecutableId
- ResourceType
- Average
- Median
- StandardDeviation
- Percentile95
- Peak
- ObservationCount
- ObservationStart
- ObservationEnd
- ConfidenceLevel

### AnomalyEvents

- EventId
- ProcessInstanceId
- ResourceType
- CurrentValue
- BaselineValue
- Deviation
- Severity
- Duration
- SystemImpact
- Description
- Timestamp

### Configuration

- ConfigurationId
- SamplingInterval
- BaselineWindow
- DetectionSensitivity
- RetentionPeriod
- MonitoringEnabled

## 4.3 Data Retention

Resource samples may accumulate rapidly.

The application should implement configurable retention policies.

Suggested initial defaults:

| Data Type | Retention |
|---|---|
| Raw resource samples | 7 days |
| Aggregated 1-minute samples | 30 days |
| Aggregated 15-minute samples | 180 days |
| Baseline profiles | Indefinite |
| Anomaly events | 180 days |
| Application inventory | Until refreshed |

The application should periodically aggregate and prune historical data.

---

# 5. Technical Architecture and Technology Stack

## 5.1 Rust Ecosystem

Proposed libraries:

| Component | Technology |
|---|---|
| Programming Language | Rust |
| Async Runtime | Tokio |
| Terminal Interface | Ratatui |
| Terminal Backend | Crossterm |
| Web Framework | Axum |
| Serialization | Serde |
| Database | SQLite |
| Database Access | SQLx |
| Logging | Tracing |
| Configuration | Figment or TOML |
| Error Handling | anyhow / thiserror |
| Windows APIs | windows-rs |
| CLI | Clap |
| Digital Signature Verification | Windows WinVerifyTrust APIs |
| HTTP API | Axum |
| Browser Styling | Topcoat CSS |
| Charts | Apache ECharts or Chart.js |

Final library selection should be validated during technical prototyping.

## 5.2 Windows Integration

The application will require access to Windows system-level information.

Potential Windows interfaces include:

| Requirement | Windows Interface |
|---|---|
| Process enumeration | Tool Help API / Process Status API |
| Process details | Windows Process APIs |
| CPU statistics | GetProcessTimes / Performance Counters |
| Memory statistics | GetProcessMemoryInfo |
| System memory | GlobalMemoryStatusEx |
| Disk I/O | Process I/O counters / ETW |
| Network I/O | ETW / Windows networking interfaces |
| Installed applications | Windows Registry |
| Digital signatures | WinVerifyTrust |
| Windows service | Windows Service Control Manager |
| System performance | Performance Data Helper / ETW |

The implementation should prefer documented Windows interfaces.

Where process-level disk or network attribution cannot be reliably obtained through basic APIs, ETW should be evaluated.

The application must document measurement limitations rather than presenting incomplete measurements as authoritative.

## 5.3 Windows Service Architecture

The monitoring engine should support two operating modes.

**Interactive Mode**

- Started manually.
- Uses the terminal interface.
- Displays live monitoring information.
- Allows profiling and configuration.

**Service Mode**

- Runs in the background.
- Starts automatically when configured.
- Performs inventory refreshes.
- Collects resource statistics.
- Evaluates anomalies.
- Writes data to SQLite.

The service and interactive application should share the same core library.

The service must operate without an interactive user session.

Appropriate Windows permissions should be used for process enumeration and data collection.

---

# 6. Nonfunctional Requirements

## NFR-001: Performance Overhead

The monitoring application must have minimal impact on the computer being monitored.

Initial targets:

- Idle CPU utilization: preferably below 1%.
- Average memory footprint: preferably below 100 MB.
- Sampling overhead: configurable.
- No unnecessary continuous disk writes.
- Efficient batch database writes.

These are engineering targets to be validated through testing, not guaranteed operating limits.

## NFR-002: Reliability

- Monitoring must recover from individual process failures.
- Process termination must not crash the monitoring engine.
- Database errors must be logged.
- Service interruptions must not corrupt historical data.
- Monitoring should resume automatically after service restart.
- Database writes should use transactions.

## NFR-003: Security

- Local-first architecture.
- No external data transmission by default.
- Restricted database permissions.
- Browser reporting bound to localhost by default.
- No automatic execution of commands based on anomaly detection.
- Sensitive process command-line information should be handled carefully.

## NFR-004: Scalability

The application should support:

- Hundreds of running processes.
- Long-running monitoring sessions.
- Configurable sampling intervals.
- Historical reporting across multiple days or weeks.

## NFR-005: Maintainability

The codebase should use modular Rust crates or clearly separated modules.

The monitoring engine must remain independent of its presentation layers.

---

# 7. Proposed Project Structure

Suggested workspace organization:

```text
winperf/
|
+-- Cargo.toml
|
+-- crates/
|   |
|   +-- winperf-core/
|   |   +-- inventory/
|   |   +-- processes/
|   |   +-- metrics/
|   |   +-- profiler/
|   |   +-- anomaly/
|   |   +-- system_health/
|   |
|   +-- winperf-windows/
|   |   +-- process_api/
|   |   +-- memory_api/
|   |   +-- disk_api/
|   |   +-- network_api/
|   |   +-- registry/
|   |   +-- signatures/
|   |   +-- service/
|   |
|   +-- winperf-storage/
|   |   +-- database/
|   |   +-- repositories/
|   |   +-- migrations/
|   |
|   +-- winperf-cli/
|   |   +-- commands/
|   |   +-- tui/
|   |
|   +-- winperf-service/
|   |
|   +-- winperf-report/
|       +-- api/
|       +-- web/
|       +-- reports/
|
+-- config/
|
+-- migrations/
|
+-- tests/
|
+-- documentation/
```

This organization is a starting point. The final crate boundaries should be determined during implementation.

---

# 8. Development Phases

The project should be implemented incrementally.

## Phase 1: Windows System Inventory Utility

**Objective:** Establish reliable access to Windows process and application information.

Deliverables:

1. Installed application enumeration.
2. Running process enumeration.
3. Process-to-application association.
4. Executable metadata collection.
5. Microsoft/third-party publisher classification.
6. Digital signature verification.
7. Basic system resource collection.
8. Terminal-based inventory display.
9. Export inventory to JSON and CSV.

Acceptance criteria:

- Successfully enumerates installed applications.
- Identifies running processes.
- Retrieves accessible executable paths.
- Identifies Microsoft-signed executables.
- Distinguishes signed, unsigned, and unknown executables.
- Handles inaccessible and terminated processes gracefully.
- Produces consistent inventory results across repeated scans.

## Phase 2: Resource Collection and Historical Storage

**Objective:** Establish the monitoring infrastructure.

Deliverables:

1. Configurable sampling engine.
2. CPU collection.
3. Memory collection.
4. Disk I/O collection.
5. Network I/O collection.
6. System-level metrics.
7. SQLite database.
8. Historical resource samples.
9. Process lifecycle tracking.
10. Basic Ratatui monitoring dashboard.

Acceptance criteria:

- Collects process statistics at configurable intervals.
- Stores historical samples.
- Correctly distinguishes process instances.
- Calculates resource consumption over time.
- Does not significantly affect normal system performance.

## Phase 3: Baseline Profiling Engine

**Objective:** Establish normal operating profiles.

Deliverables:

1. Rolling baseline calculations.
2. Average and median calculations.
3. Standard deviation.
4. 95th percentile calculations.
5. Baseline confidence indicators.
6. Baseline management.
7. Baseline visualization in the terminal.

Acceptance criteria:

- Generates baseline profiles from historical samples.
- Supports multiple baseline windows.
- Identifies insufficient historical data.
- Updates baselines as additional observations are collected.

## Phase 4: Anomaly Detection Engine

**Objective:** Identify applications behaving abnormally.

Deliverables:

1. CPU anomaly detection.
2. Memory anomaly detection.
3. Memory growth detection.
4. Disk I/O anomaly detection.
5. Network I/O anomaly detection.
6. Sustained deviation detection.
7. System resource pressure correlation.
8. Anomaly severity classification.
9. Anomaly history.

Acceptance criteria:

- Detects significant deviations from established baselines.
- Avoids treating every temporary spike as an anomaly.
- Correlates process activity with system-level performance degradation.
- Explains why an anomaly was generated.
- Supports configurable thresholds.

## Phase 5: Windows Background Monitoring Service

**Objective:** Support unattended monitoring.

Deliverables:

1. Windows service implementation.
2. Service installation and removal.
3. Automatic startup configuration.
4. Background resource collection.
5. Baseline evaluation.
6. Persistent anomaly detection.
7. Service health monitoring.
8. Recovery after unexpected shutdown.

Acceptance criteria:

- Service operates without an interactive terminal.
- Monitoring starts automatically when configured.
- Data collection continues after the user closes the terminal application.
- The service and terminal application share the same monitoring engine.

## Phase 6: Browser Reporting Application

**Objective:** Provide comprehensive historical and real-time reporting.

Deliverables:

1. Rust/Axum reporting backend.
2. Topcoat CSS user interface.
3. System performance dashboard.
4. Process resource rankings.
5. Historical performance charts.
6. Application detail reports.
7. Baseline-versus-actual charts.
8. Anomaly investigation dashboard.
9. CSV/JSON export.

Acceptance criteria:

- Browser can access locally collected data.
- Charts accurately represent historical resource consumption.
- Applications can be ranked by individual resource categories.
- Users can investigate historical anomalies.
- Reporting does not interfere with the monitoring service.

## Phase 7: Optimization and Advanced Diagnostics

Potential enhancements:

- Context-sensitive baselines.
- Scheduled workload detection.
- Improved memory leak detection.
- ETW-based process-level I/O attribution.
- Windows performance counter integration.
- Resource consumption forecasting.
- Application behavior comparisons across software versions.
- Automated diagnostic recommendations.
- Optional notifications.

---

# 9. Initial User Experience

The expected workflow is:

## First-Time Setup

1. Install WinPerf.
2. Run the inventory scan.
3. Review installed and running applications.
4. Verify Microsoft and third-party classifications.
5. Start baseline profiling.

## Baseline Establishment

1. Run the application during normal daily computer usage.
2. Collect resource consumption over several days.
3. Build initial application profiles.
4. Establish confidence levels.
5. Transition to continuous monitoring.

## Normal Monitoring

1. Install or start the Windows monitoring service.
2. Allow monitoring to run in the background.
3. Review the terminal dashboard when needed.
4. Open the browser reporting interface to investigate performance.

## Performance Degradation Investigation

When the computer becomes sluggish:

1. Open the terminal dashboard or browser report.
2. Review current system resource utilization.
3. Identify processes with abnormal resource consumption.
4. Compare their current behavior against historical baselines.
5. Review the duration and severity of detected anomalies.
6. Determine which applications are contributing to system resource pressure.

---

# 10. Important Technical Considerations and Risks

## 10.1 Process Identity

Windows can reuse PIDs.

The application must not use PID alone as a permanent process identifier.

A combination of PID and process creation timestamp should be used to distinguish process instances.

## 10.2 Resource Attribution

Not all resource consumption can be attributed equally well to individual processes.

CPU and memory statistics are relatively straightforward to collect.

Disk and especially network activity may require additional Windows interfaces and event tracing.

The system should indicate when a metric is unavailable or only partially attributable.

## 10.3 Baseline Accuracy

An application does not necessarily have one normal operating state.

Resource consumption varies with workload.

The baseline engine must avoid flagging legitimate application activity as abnormal.

The initial statistical implementation should favor explainability and allow thresholds to be adjusted.

## 10.4 Database Growth

Sampling every five seconds across hundreds of processes can produce a substantial volume of records.

The application should implement:

- Batched inserts.
- Historical aggregation.
- Configurable retention.
- Database maintenance.
- Index optimization.

## 10.5 Monitoring Overhead

A monitoring application that consumes substantial resources would defeat its own purpose.

Resource collection, database writes, and anomaly calculations should be designed to minimize overhead.

## 10.6 Microsoft Application Identification

A Microsoft digital signature identifies the publisher, not necessarily whether a program is a core Windows component.

The classification model must preserve this distinction.

---

# 11. MVP Definition

The first usable product should focus on the following capabilities:

1. Installed application inventory.
2. Running process inventory.
3. Microsoft versus third-party classification.
4. CPU monitoring.
5. Memory monitoring.
6. Basic disk I/O monitoring.
7. Basic network I/O monitoring.
8. Historical SQLite storage.
9. Baseline generation.
10. Statistical anomaly detection.
11. Ratatui terminal dashboard.
12. Basic browser reporting.

The MVP should prioritize accurate collection and meaningful baseline calculations over an extensive reporting interface.

---

# 12. Initial Design Decisions

The following are proposed defaults, subject to validation:

| Decision | Initial Recommendation |
|---|---|
| Operating System | Windows 11 x64 |
| Language | Rust |
| Architecture | Modular Cargo workspace |
| Monitoring Engine | Shared Rust library |
| Terminal Interface | Ratatui |
| Background Operation | Windows Service |
| Web Framework | Axum |
| Browser Styling | Topcoat CSS |
| Charting | Apache ECharts |
| Database | SQLite |
| Sampling Interval | 5 seconds |
| Initial Baseline Period | 7 days |
| Raw Data Retention | 7 days |
| Aggregated Data Retention | 180 days |
| Anomaly Detection | Statistical methods |
| Deployment | Local workstation |
| Network Access | Localhost only |

---

# 13. Future Enhancements

The architecture should leave room for the following features without requiring substantial changes to the core engine:

- Multiple Windows workstation monitoring.
- Remote reporting dashboards.
- Comparison of application behavior before and after updates.
- Historical computer performance comparisons.
- Detection of recurring performance degradation patterns.
- Identification of applications that gradually consume more resources.
- Automated diagnostic explanations.
- Recommendations for investigating problematic applications.
- Exportable diagnostic packages for troubleshooting.
- Optional integration with Windows Event Logs.

---

# 14. Product Success Criteria

The project will be considered successful when it can:

1. Reliably inventory installed applications and running processes.
2. Establish useful historical resource-consumption profiles.
3. Identify statistically significant behavioral deviations.
4. Distinguish ordinary resource spikes from sustained abnormal behavior.
5. Correlate abnormal application behavior with overall system performance degradation.
6. Identify the applications most likely contributing to sluggishness.
7. Present useful historical and real-time information through terminal and browser interfaces.
8. Operate continuously with minimal performance overhead.

**The ultimate measure of success:** When the computer starts becoming sluggish or unresponsive, WinPerf should provide enough historical and real-time evidence to help identify which application or process is responsible, what resource it is consuming, and how its behavior differs from its established normal operating pattern.

---

# 15. Additional Architectural Recommendations

## 15.1 Use One Monitoring Engine, Not Two

Keep the monitoring engine independent of the terminal and web interfaces.

```text
+---------------------------------------------+
|             WinPerf Core (Rust)             |
| Inventory | Collection | Profiling          |
| Anomaly Detection | System Health           |
+----------------------+----------------------+
                       |
          +------------+------------+
          |                         |
          v                         v
+----------------------+  +----------------------+
| Ratatui              |  | Windows Service       |
| Interactive terminal|  | Background monitoring|
+----------------------+  +----------------------+
          |                         |
          +------------+------------+
                       |
                       v
              +----------------+
              | SQLite         |
              | Shared history |
              +-------+--------+
                      |
                      v
              +----------------+
              | Axum + Topcoat |
              | Browser reports|
              +----------------+
```

This avoids maintaining separate implementations of profiling and anomaly detection.

## 15.2 Do Not Rely Exclusively on Percentage Deviation

Suppose an application normally consumes 0.5% CPU and temporarily increases to 2%. That is a fourfold increase, but probably insignificant.

Conversely, an application normally consuming 15% CPU that increases to 50% may be much more concerning.

Implement a detection model that considers:

- Absolute resource consumption.
- Deviation from historical baseline.
- Duration of abnormal consumption.
- Overall system resource pressure.
- Rate of resource consumption growth.

This is particularly important for identifying the actual cause of sluggishness rather than simply ranking applications by resource usage.

## 15.3 Make ETW a First-Class Consideration

Windows Event Tracing for Windows (ETW) deserves particular attention. It can provide more detailed information about process-level disk and network activity than basic process enumeration APIs. Prototype this early rather than discovering its limitations late in development.

## 15.4 Recommended First Implementation Deliverable

Begin with a small, independent Windows diagnostic utility before building the complete application.

Its purpose is to establish which Windows APIs and Rust libraries can reliably retrieve all the metrics needed, including their accuracy, permissions, and collection overhead.

That utility will become the technical foundation for Phase 1.

## 15.5 Recommended Next Document

The next logical deliverable is a **Technical Architecture and Software Design Specification (SDS)**, including:

- Rust crate boundaries.
- Windows API selection.
- SQLite schema and indexes.
- Sampling pipeline.
- Process identity and lifecycle handling.
- Baseline calculation algorithms.
- Anomaly-detection algorithms.
- Windows service design.
- Reporting API contracts.
- Testing strategy.
