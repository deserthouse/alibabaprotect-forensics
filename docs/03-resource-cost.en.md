# 03 · Resource-Cost Measurements

**English** · [简体中文](03-resource-cost.md)

The motivation for cleanup was "it's eating CPU". This doc provides the **measured data and metric definitions**, and an honest answer to "**what it does while CPU is high**".

---

## 1. Measured data

### Sample set 1 (pre-cleanup, same process at two points in time)

| Metric | Sample A | Sample B |
|---|---|---|
| Process | `AlibabaProtect.exe` | same |
| PID | 6108 | 6108 |
| Start time | 09-21 17:21:49 | 09-21 17:21:49 |
| **Cumulative CPU time** | **4,875.5 s** | **5,077.5 s** |
| Working set (memory) | 74.0 MB | 75.7 MB |
| Threads | 39 | 43 |
| Handles | — | 968 |
| Sample time | 09-22 00:07 | 09-22 00:23 |
| Parent | `services.exe` (launched by SCM) | same |
| Command line | `"C:\Program Files (x86)\AlibabaProtect\1.0.70.3194\AlibabaProtect.exe"` | same |

### Metric definitions: from "cumulative seconds" to "usage percentage"

Cumulative CPU time must be **divided by process uptime** to get average utilization:

```
Uptime A = 09-22 00:07 − 09-21 17:21:49 = 6.75 h = 24,300 s
Average usage (single core) = 4,875.5 ÷ 24,300 ≈ 20.1% of one core

Uptime B = 09-22 00:23 − 09-21 17:21:49 = 7.02 h = 25,260 s
Average usage (single core) = 5,077.5 ÷ 25,260 ≈ 20.1% of one core
```

**Two independent points in time produce the same number (20.1%) — this is not transient jitter but its steady-state behavior.**

### ⚠️ Conversion: per-core percentage ≠ whole-machine percentage

This machine has **16 logical processors**:

```
Whole-machine share = 20.1% ÷ 16 ≈ 1.26%
```

**Saying "20% of one core" means "eating a fifth of the machine" is wrong** (off by 16×). This repo always states which metric is used.

> Metric note: the above is average utilization derived from **cumulative** values, to convey magnitude; for cross-process comparison the stricter metric is the **average per-core utilization** (i.e., the formula itself).

---

## 2. Limitations of this data

| Limitation | Impact |
|---|---|
| Only **two points in time**, no continuous curve | No range of variation; cannot rule out "heavier in some intervals" |
| Instantaneous usage exists only as **one** 1-second delta estimate (~45% of one core / ≈2.8% whole-machine, see note below) | Single sample, crude method — magnitude reference only, not a peak conclusion |
| No **thread-level** sampling | Total process time only; unknown which threads consumed it |
| **Single-machine data** | Other configurations/versions may behave differently |
| Cumulative values affected by **uptime** | Corrected via average utilization, see §1 |

**These limitations do not change the conclusion "it steadily consumes ~20% of one core".**

> **Note (instantaneous sample)**: during the pre-remediation process inventory, one 1-second CPU-delta estimate was taken: `AlibabaProtect ≈ 2.8% whole-machine` (÷16 ≈ **45% of one core**). Single reading, short window, crude method — it only shows the instantaneous level can run well above the 20%-of-one-core steady average; it does not bound the peak.

---

## 3. "What is it actually doing while CPU is high" — the honest answer

This is the **one question this repo cannot answer with existing evidence**. The boundary:

### 3.1 What direct evidence shows

| Fact | Evidence |
|---|---|
| It makes **no TCP connections** | Measured process network connections = **0** |
| It runs many threads | 39–43 threads |
| It holds many kernel objects | 968 handles |
| It ships a full set of "scanning" modules | `FileScanner.dll` / `FileWatch.dll` / `FileMonitor.dll` / `PathMon.dll` / `ProcessScanner.dll` / `HealthCheck.dll` / `Scheduler.dll` |
| It has a performance-monitoring module | `perfmonsdk.dll` (`Perfmon` `1.2.68`) |
| It obtains the current process's module name and queries version info | Unencrypted error-string remnants (see 02 §4.2) |

### 3.2 What can only be inferred (**labeled as inference**)

Assembling the facts above, the **inference best supported by evidence** is:

> The CPU consumption comes from **periodic patrol work** — scheduled by `Scheduler.dll`, with `FileScanner` / `PathMon` / `ProcessScanner` performing enumeration and verification, `perfmonsdk` collecting local performance data, and `HealthCheck` aggregating.

**But this is only an inference.** Reasons:

1. **"Has scanning modules" ≠ "is scanning while CPU is high"** — the modules may be idle.
2. Without thread-level stack sampling, **not one piece of evidence attributes CPU time to a specific function**.
3. Configuration and strings are transformed — **the schedule, scan scope, and verification targets are invisible**.

### 3.3 What it would take to actually determine this

For anyone continuing the dig, these are the methods that turn "inference" into "conclusion":

| Method | Command / tool | What it yields |
|---|---|---|
| **CPU stack sampling** | `wpr -start cpu -filemode` (Windows Performance Recorder) → open in WPA | **Which module/function the CPU time lands on** (most decisive) |
| Live thread stacks | Process Explorer → process properties → Threads → Stack | What is executing right now |
| File/registry activity | Process Monitor, filtered by process name | Which paths it **actually** accesses, how often |
| Driver IOCTL semantics | IOCTL tracing on the driver | The command meanings of `\\.\CtrlSM` |
| Schedule period | Procmon timestamp-interval statistics | Whether patrol runs every few seconds or minutes |

**Conclusion: until stack-sampling evidence exists, "what it does at high CPU" should be stated as "suspected relation to periodic patrol/self-verification — unproven".**

---

## 4. Why this doesn't matter for the "should I clean it" decision

Note the logical chain:

```
The user has already uninstalled the Alibaba-family clients
        ↓
The user does not need this component's function
        ↓
Therefore "what exactly it does" is no longer a decision premise
```

**The decision basis is not "it did something bad" but "I don't need it, and it consumes resources".** That basis needs only §1's measured data: 20% of one core, sustained for 7 hours, resident as a system service. (Note: during the investigation the Alibaba clients were still installed on both machines; "still there after the clients are uninstalled" is the companion guide's applicability scenario, not a measured claim of this repo.)

Stating "unproven behavior" as "proven harm" violates the evidence principles and would lower the credibility of this entire document. **This is a deliberate blank this repo keeps.**

---

Prev: [02 · Behavior analysis](02-behavior-analysis.en.md) ｜ Next: [04 · Why it's hard to remove](04-why-hard-to-remove.en.md)
