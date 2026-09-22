# 04 · Why It Doesn't Come Clean

**English** · [简体中文](04-why-hard-to-remove.md)

The failures encountered during cleanup are not random — behind them are **three independent mechanisms**. Understanding the three explains why "deleting once" doesn't work.

---

## 1. Overview: three re-appearance paths

| Path | Trigger | Measured evidence |
|---|---|---|
| **A. Callback self-protection** | While the service/driver still runs, any "disable / kill / delete" operation gets rolled back | Driver embeds `FltRegisterFilter` + `CmRegisterCallback` + `PsSetCreateProcessNotifyRoutine` (see 02) |
| **B. SCM auto-recovery** | After the service crashes or is killed, the Service Control Manager restarts it per its recovery policy | System-log **`7031`** verbatim (see §3); **independent of any watchdog process** |
| **C. Client re-installation** | Alibaba-family clients (Taobao desktop / AliWangWang etc.) check and reinstall on launch/update | System-log **`7045`** recorded **many** installs of the same driver service; client directories contain `SafeGuard\` and `pc-sdk-setup.exe` |

**Path B is the easiest to overlook.** Many people kill the process, think it's over, and 60 seconds later it's back — that isn't "failed to kill", it's SCM bringing it up per policy.

---

## 2. Path A: how callback self-protection manifests

| Phenomenon | Mechanistic explanation (with confidence) |
|---|---|
| After `sc config ... start= disabled`, `Start` reverts to `2` (auto) within seconds | The **revert was observed**; the mechanism is **consistent with** the driver's registered registry callback (`CmRegisterCallback`) — **inference**. The reverting agent was not individually traced (a user-mode process polling and writing back, e.g. `RestartService.exe`, is also possible) |
| `Remove-Item` on the install directory reports `Access denied` | The file-system minifilter (`FltRegisterFilter`, with independent registry-side configuration evidence — see 02) intercepted the delete |
| The process returns after being killed | Process-creation callback (`PsSetCreateProcessNotifyRoutine`) + Path B |

### The specific failures measured, and the truth behind them

| Operation | Return | Truth |
|---|---|---|
| `sc stop AlibabaProtect` | **1052** (control not valid for this service) | **Normal**: the service implements no stop handler; not a permission problem |
| `sc delete AlibabaProtect` | Success | ✅ The service entry is marked deleted and SCM won't restart it; **the running process is not terminated by this** (measured: process alive after delete, then explicitly killed — see `evidence/cleanup-log.txt` phase 1c) |
| `sc stop AliPaladin` | 1062 / 1052 | **Normal**: kernel drivers cannot be stopped online |
| Deleting the `AliPaladinEx64.sys` file | Reports a "safe delete" error | ⚠️ **False error** — re-checking confirmed the file **was actually deleted** |

> **"Error returned ≠ operation failed"** is a pitfall worth remembering on its own: driver-file deletion can report an error while the file is actually gone. After cleanup, always **verify for real** (`Test-Path`); never conclude from return codes alone.

---

## 3. Path B: SCM auto-recovery (event verbatim)

From the system log (`Service Control Manager`):

```
[id=7031] The Alibaba PC Safe Service service terminated unexpectedly, occurrence 1.
          The following corrective action will be run in 60000 milliseconds: restart the service.
```

(Original entry in Chinese; translated for this doc.)

Key points:

- **The recovery depends on no watchdog process** — the restart is performed by SCM (the Service Control Manager), regardless of whether the software's own processes are alive. **Killing the process alone is therefore useless.**
- **The one countermeasure: delete the service itself** (`sc delete`), not disable, not kill. With the service entry gone, SCM has nothing to restart.
- Related events: `7034` (unexpected termination, no action), `7023` (stopped due to error) — useful for reconstructing crash history.

### 3.1 Independent second evidence: `FailureActions` in the registry

The `7031` above is a **runtime log**. The same policy is also visible in the **registry** (full decoding in `evidence/service-failureactions.txt`):

```
HKLM\SYSTEM\CurrentControlSet\Services\AlibabaProtect\FailureActions
  44 raw bytes, read as DWORDs:
  [ 0] 0            [ 1] 0            [ 2] 0            [ 3] 3
  [ 4] 20           [ 5] 1  ←SC_ACTION_RESTART          [ 6] 0xEA60 = 60000
  [ 7] 1  ←SC_ACTION_RESTART          [ 8] 0xEA60 = 60000
  [ 9] 1  ←SC_ACTION_RESTART          [10] 0xEA60 = 60000
```

| Read directly from the data | Corresponds to the log |
|---|---|
| **3×** `0xEA60 = 60000` ms delay | Log: `will be run in 60000 milliseconds` |
| **3×** value `1` = `SC_ACTION_RESTART` (restart the service) | Log: `restart the service` |
| First 3 DWORDs zero (no reboot-message / custom-command set) | — |

**Two mutually independent pieces of evidence (registry configuration + runtime log) point to the same conclusion** — the ideal case under the "correlation ≠ causation" principle: not temporal coincidence, but **the same fact recorded in two different places**.

> Evidence hygiene: `FailureActions` is a binary structure written by SCM; header-field layouts may differ across Windows versions. The table above lists only correspondences **directly readable from the data**, without forcing interpretations of unverifiable offsets. The full raw value is preserved in `evidence/service-AlibabaProtect.reg` for review.

---

## 4. Path C: log evidence of repeated installation

Event `7045` ("a service was installed") preserves the full record of every service install:

```
[id=7045] A service was installed in the system.
          Service Name: AliPaladin
          File Name: C:\WINDOWS\system32\drivers\AliPaladinEx64.sys
          Service Type: kernel-mode driver
          Start Type: auto start
```

**Measured result: this one driver service was recorded installed `24` times between 2026-07-11 and 2026-09-18.**

```
2026-07-11 12:04:38   ← earliest (same minute as the AlibabaProtect service's first install)
2026-07-29 21:31:51
2026-07-29 21:33:28   ← two entries within one minute
2026-07-30 10:48:43
2026-07-31 09:54:10
2026-08-08 22:27:23
2026-08-13 12:49:03
2026-08-15 00:03:32
2026-08-15 00:06:46
2026-08-23 15:02:38
2026-08-24 23:20:30
2026-08-26 13:32:49
2026-08-26 13:35:04
2026-08-27 22:25:49
2026-08-28 16:30:13
2026-08-28 16:31:35
2026-09-03 17:38:56
2026-09-03 22:36:03
2026-09-07 02:02:47
2026-09-11 21:00:09
2026-09-11 21:02:48
2026-09-13 00:46:29
2026-09-15 17:13:14
2026-09-18 16:22:01
```

**On average once every ~3.5 days, with several same-minute pairs** (`07-29`, `08-15`, `08-26`, `08-28`, `09-03`, `09-11` each have one) — indicating a **routinized automatic behavior**, not chance.

This evidence is exceptionally valuable: **looking only at current state (service exists) would never reveal "it has been installed 24 times"**. Only install history exposes the pattern.

> **Evidence hygiene**: `evidence/scm-events.txt` also excludes **5 `7045` events from services mistakenly created during this machine's own investigation experiments** (service file names pointing at `notepad.exe` / `blocked.exe`). They are not product behavior; mixing them in would mislead, so they are listed separately at the end of the evidence file with a note.

### Three leads on "who installs it"

| Lead | Detail |
|---|---|
| Scheduled tasks | `AliProctectUpdate`, `AliUpdater` (note: the former is the vendor's own spelling, including the `Proctect` typo — not a typo of this repo) |
| Installers inside client directories | Checker and packages under `SafeGuard\`; `pc-sdk-setup.exe` (~37 MB, matching the CI project name `pc-sdk-build`) |
| Updater processes | `AliProtectUpdate.exe`, `AlibabaProtectCon.exe` |

### A measured re-enable event

**After one Taobao desktop update, the `AliUpdater` scheduled task was switched back to enabled.** That is:

> The client's update flow turns the "check and install AlibabaProtect" autostart **back on**. Tasks disabled during cleanup are restored by the next client update.

⇒ Direct proof: **one-time cleanup cannot maintain a clean state**; an anti-recurrence measure is needed (see 06).

### Measured on a semi-cleaned machine: re-install attempts blocked by "file missing" (second machine)

On a machine where **only files were deleted, with no interception** (no IFEO), `AliUpdater` still ran hourly, but every attempt failed:

| Observation | Evidence |
|---|---|
| The updater's expected version directory doesn't exist; every attempt fails before landing | `IntegrityCheck.ini` plaintext error `[C:\Program Files (x86)\AlibabaProtect\1.0.70.988\] is not exist` |
| Triple coincidence of attempt traces with task times | Task run time = new ERROR log entry in `Logs\` = `IntegrityCheck.ini` rewrite time |
| Attempts continued from self-cleanup (2026-03) to collection day (2026-09), **never stopping, never succeeding** | ERROR logs counted per day; main-program INFO logs stop at cleanup day, no successful run since |

Two lessons (full data in `evidence/partial-cleanup-state.txt`):

1. **"Files missing" is itself a blocker** — re-installation Path C requires "the installer can land";
2. **"Not reinstalled" ≠ "not trying"** — the semi-cleaned state keeps producing low-noise attempt traces indefinitely. This is also **an independent evidence path** for doc 05's "tried but couldn't get in" determination (not relying on IFEO / Prefetch).

---

## 5. One observation that can only be labeled "suspected"

During the investigation it was also found that all `7000` (service failed to start) events for `AliPaladin` **clustered in three consecutive starts on 09-21**:

```
[id=7000] The AliPaladin service failed to start due to the following error:
          A device attached to the system is not functioning.
  └─ 2026-09-21 17:14:02
  └─ 2026-09-21 17:17:10
  └─ 2026-09-21 17:21:48
```

The same error appeared once each on 09-05 and 09-14 as well — **5 in total**. Three starts each reporting the same error within ~20-second windows indicates **the driver persistently failed to initialize in that window**.

**But this cannot be a causal conclusion**, because:

- Many kernel drivers were loaded at the same time; the failure cannot be attributed to this one alone
- "Failed to start" may be the **result** of a crash-restart rather than its cause
- Temporal proximity ≠ causation

**Correct statement**: `suspected correlation, unproven; the driver has since been removed, and this potential factor disappeared with it.`

> **Contrast sample**: on the other machine, `7000` events from a **dangling** `AliPaladin` service key (`Start=Auto` with the driver file deleted) **can be directly attributed** (43 entries since 2026-05, see `evidence/partial-cleanup-state.txt` §3). Same error code, entirely different attribution conditions — which is exactly why the "reasons this can't be attributed" are listed one by one above.

---

## 6. The correct remediation order

The three mechanisms dictate an **order that must not be shuffled**:

```
① First disable the updater scheduled tasks
     └─ prevents re-installation mid-cleanup

② Then sc delete the services (main + driver), then explicitly kill the process
     └─ cuts off Path B (SCM auto-recovery)
     └─ note: delete only marks for deletion and does not terminate the running
        process — kill it separately before ③

③ Then delete files and directories
     └─ the minifilter is no longer loaded by now; deletes usually succeed

④ Reboot — mandatory
     └─ kernel drivers/filters only truly unload on reboot
     └─ ⚠️ with Fast Startup enabled, "shut down then power on" does NOT rebuild
        the kernel session — use Restart specifically

⑤ Verify after reboot
     └─ use doc 05's method to prove it didn't come back
```

### If ② ③ are blocked: the two-phase plan

If the running service refuses all modification, detour with **two reboots**:

1. **Phase 1**: while the service still runs, only `sc config AlibabaProtect start= disabled`
2. **Reboot** (it won't be started; process and file locks disappear)
3. **Phase 2**: after reboot, run the full ②–⑤ (usually unobstructed now)

Concrete commands are in the companion [alibabaprotect-uninstall-guide](https://github.com/deserthouse/alibabaprotect-uninstall-guide).

---

## 7. Evidence sources for this doc

| Evidence | File |
|---|---|
| Service registry export (incl. `DisplayName` / `ImagePath` / `FailureActions`) | `evidence/service-AlibabaProtect.reg` |
| Driver service registry export (incl. `Group` / `Altitude` / `DependOnService`) | `evidence/service-AliPaladin.reg` |
| `FailureActions` decoding (3 × 60000 ms auto-restart) | `evidence/service-failureactions.txt` |
| SCM events (7031 / 7034 / 7000 / 7045, 34 entries) | `evidence/scm-events.txt` |
| Cleanup session log | `evidence/cleanup-log.txt` |
| Callback-registration evidence | `evidence/driver-AliPaladin-functions.txt` |
| Registry-side minifilter evidence | `evidence/service-AliPaladin-minifilter.txt` |
| Persistent re-install attempts, semi-cleaned machine | `evidence/partial-cleanup-state.txt` |

---

Prev: [03 · Resource-cost measurements](03-resource-cost.en.md) ｜ Next: [05 · Execution-level forensics](05-execution-forensics.en.md)
