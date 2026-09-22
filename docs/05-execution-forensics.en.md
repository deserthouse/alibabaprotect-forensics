# 05 · Execution-Level Forensics: Proving Whether It Actually Ran

**English** · [简体中文](05-execution-forensics.md)

The most common post-cleanup question isn't "was it deleted" — it's this:

> **It isn't running now — is that because "nothing tried to start it", or because "something tried and was blocked"?**

The two conclusions are opposites: the former means the anti-recurrence measure hasn't been tested yet; the latter is what actually proves the interception works. This doc records two determination methods that **require no debugger**.

---

## 1. Prefetch: has the program **successfully executed**

### Principle

The Windows Prefetch mechanism generates a `<image-name>-<hash>.pf` file under `C:\Windows\Prefetch\` for **every executable that actually started**.

> **The existence of `C:\Windows\Prefetch\<name>.pf` is strong evidence that "this image successfully started at some point".**

### The key technique: cross it with "last access time"

Prefetch alone only proves "it ran". The value comes from crossing two dimensions:

| Prefetch | File `LastAccessTime` | Verdict |
|---|---|---|
| Present | Recent | It really ran |
| **Absent** | **Recent** | ⭐ **A start was attempted but failed at process creation** — the fingerprint of **interception working** |
| Absent | Stale | Never attempted |

**Why this holds**: when starting a process, the kernel **opens the image file first** (updating access time) and only then proceeds to `CreateProcess`. If blocked at the Image File Execution Options (IFEO) layer, **the file was "touched" but no process was ever created** — leaving the "accessed but no record" combination.

### Measured case

During one anti-recurrence verification, the target program should have attempted to start on an external trigger. Inspection:

```powershell
Get-ChildItem C:\Windows\Prefetch -Filter "ALIBABAPROTECT*"   # → none
Get-ChildItem C:\Windows\Prefetch -Filter "ALIPALADIN*"      # → none

(Get-Item '...\AlibabaProtectCon.exe').LastAccessTime         # → falls exactly on the trigger moment, to the second
```

**Neither key executable has a Prefetch record, yet one's access time lands exactly on the trigger second** ⇒ ruling out "it never tried"; the conclusion is "**it tried, and couldn't get in**".

**Control group**: in the same trigger event, the **upstream updater** (not intercepted) **does** have a Prefetch record — further confirming "the trigger really happened", rather than a misjudged trigger moment.

### Practical commands

```powershell
# Has any of these programs run?
Get-ChildItem C:\Windows\Prefetch -Filter "*.pf" |
    Where-Object { $_.Name -match 'ALIBABAPROTECT|ALIPALADIN|PC-SDK' } |
    Select-Object Name, LastWriteTime

# All programs run in the last N hours (rebuild an execution timeline)
Get-ChildItem C:\Windows\Prefetch -Filter "*.pf" |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
    Sort-Object LastWriteTime -Descending |
    Select-Object LastWriteTime, Name
```

> `LastWriteTime` is the program's **last run moment** — enough to rebuild a second-precision execution timeline.

---

## 2. The one-shot probe experiment: directly proving "interception works"

Prefetch is **indirect** evidence. To **directly** prove the interception mechanism actually blocks process creation, the cleanest approach is a **self-verifying experiment with a disposable name** — a brand-new filename, first prove it **can** run, add the interception, prove it **can't**, then clean everything up.

### Design requirements

| Requirement | Approach |
|---|---|
| Zero risk | Use a **disposable image name** (`IFEO_PROBE_TEST.exe`) that affects no real program |
| Executable probe | A copy of the system's own `hostname.exe` (deterministic output, no side effects) |
| Before/after control | Run once **before** adding the interception (should succeed) and once **after** (should fail) |
| Restorable | At the end, delete the IFEO key + delete the probe file |
| No interference with existing config | At the end, verify the **4 production interceptions** are still in place |

### Full experiment record

```
=== Probe experiment: proving the IFEO interception actually works (disposable name, zero risk) ===

--- 1) Create an executable probe (copy of system hostname.exe) ---
  Probe file = ...\tests\IFEO_PROBE_TEST.exe | exists=True | size=40960

--- 2) Run once BEFORE interception (should execute successfully) ---
  Result = '<hostname>'  exit=0   → ✅ executes normally (as expected)

--- 3) Add the IFEO interception (Debugger → nonexistent path) ---
  Written: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
           Image File Execution Options\IFEO_PROBE_TEST.exe
           Debugger = C:\Windows\System32\BLOCKED-By-Admin-No-Exec.exe

--- 4) Run once AFTER interception (should fail) ---
  Result = CreateProcess failed: "The system cannot find the file specified."
  → verdict: ✅ interception effective (CreateProcess refused)

--- 5) Clean up the probe (delete IFEO key + delete probe file) ---
  IFEO key deleted = True
  Probe file deleted = True

--- 6) Confirm the 4 production interceptions remain ---
  AlibabaProtect.exe        ✅ BLOCKED
  AliProtectUpdate.exe      ✅ BLOCKED
  AlibabaProtectCon.exe     ✅ BLOCKED
  pc-sdk-setup.exe          ✅ BLOCKED
  IFEO subkey count = 68  (expected 68)
```

### What this experiment proves

| Conclusion | Strength |
|---|---|
| `Debugger` pointing at a nonexistent path ⇒ **`CreateProcess` fails outright** | **Directly proven** (same program: succeeds before, fails after) |
| Interception works **by image name**, independent of file path | **Directly proven** (probe in a temp directory, still blocked) |
| Existing 4 production interceptions unaffected | **Directly verified** (subkey count identical before and after) |
| Fully restorable after cleanup | **Verified** (key and file both deleted) |

Raw record in `evidence/ifeo-probe-log.txt`.

> The value of this experiment: **not "the author believed it would work", but "the author made it try once and watched it fail"**. Every mechanism-level conclusion should be held to this standard.

---

## 3. Limitations

| Limitation | Notes |
|---|---|
| Prefetch may be disabled | On SSDs the OS may disable prefetch by default. **First confirm `C:\Windows\Prefetch` has content**, or the whole method is void |
| Prefetch may be cleaned | Cleaner utilities delete `.pf` files |
| **`LastAccessTime` updating may be off by default** | On Windows 10 1803+ NTFS last-access updating defaults to "System Managed": **off by default when the system drive > 128 GB** (`fsutil behavior query disablelastaccess` to check). In that case the "access time lands on trigger moment" fingerprint **will not appear**, leaving only the Prefetch-absent leg (proving "never ran successfully" but unable to distinguish "never tried" from "blocked"). On this machine the fingerprint worked, meaning the feature was enabled here |
| Records generated only for programs "worth prefetching" | Short-lived / tiny programs may generate none |
| No command-line arguments | Cannot tell "how it was started" |
| Can be forged/cleared | Unreliable in adversarial settings |
| Probe experiment needs admin | Writing IFEO keys under `HKLM` requires elevation |

**Conclusion: Prefetch suits "quick, zero-cost verification of execution"; the probe experiment suits "one-time confirmation that the interception mechanism works". Neither is suitable as sole evidence in an adversarial environment.**

---

## 4. When to use which

| Scenario | Use |
|---|---|
| Routine check "did it self-start recently" | **Prefetch** (seconds, read-only) |
| First-time anti-recurrence setup, confirming interception really works | **One-shot probe experiment** (once is enough) |
| Suspecting a client update triggered reinstallation | **Prefetch + SCM `7045` events** (cross timeline, see 04) |
| Needing evidence of "tried but was blocked" | **Prefetch absent + `LastAccessTime` recent** combination |

---

Prev: [04 · Why it doesn't come clean](04-why-hard-to-remove.en.md) ｜ Next: [06 · Preventing recurrence](06-prevent-recurrence.en.md)
