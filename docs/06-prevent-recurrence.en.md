# 06 · Preventing Recurrence: Blocking the Named Executables

**English** · [简体中文](06-prevent-recurrence.md)

## The problem

Cleanup is one-time, but **reinstallation is continuous**. Three measured paths (details in [04](04-why-hard-to-remove.en.md)):

| Path | Trigger | Measured evidence |
|---|---|---|
| **Client re-installation** | Alibaba-family clients check and reinstall on launch/update | `SafeGuard\` checkers and installers inside client directories; log `7045` recorded **many** installs of the same driver service |
| **SCM auto-recovery** | After a crash, the Service Control Manager restarts the service per policy | Log `7031`: "the following corrective action will be run in 60000 milliseconds: restart the service" |
| **Watchdog config rollback** | The resident driver monitors its own registry configuration and reverts it | The companion driver embeds `CmRegisterCallback` |

**Conclusion: one-time cleanup is not enough.** This doc discusses **how to make these executables unable to start — without modifying any client file**.

---

## 1. Interception targets (4, determined by measurement)

| Image name | Role | Why it must be blocked |
|---|---|---|
| `AlibabaProtect.exe` | Main process | The core executable |
| `AliProtectUpdate.exe` | Updater | Re-fetches and reinstalls |
| `AlibabaProtectCon.exe` | Checker/connector | Attempts to start when triggered by clients |
| `pc-sdk-setup.exe` | Installer (~37 MB) | **The one that actually performs the installation** |

> **Before enabling**: confirm these 4 names have **no same-named third-party programs on your own machine** (full-disk search). IFEO applies **by filename** globally; a mistaken block would affect unrelated programs.

---

## 2. Option comparison (with measured results)

| Option | Principle | Pros | Cons / measured result |
|---|---|---|---|
| ⭐ **IFEO image blocking** | Replace the launch target **by image filename** with a nonexistent path → `CreateProcess` fails | Pure registry; **no target-file modification**; **global by name** (one rule covers every copy); deleting the key restores | Matches **by filename** (same-named programs blocked too); the caller receives a launch failure |
| File ACL deny-execute | Set Deny-Execute on the exe | File-precise | ❌ **requires modifying the target file** (if the target sits inside someone else's client directory, you're touching their program) |
| Rename / zero-byte | Make the file unrunnable | Intuitive | ❌ modifies the file; client updates restore it |
| **Deny ACE on the service registry key** | Prevent the service from being re-registered | Deterministic in theory | ❌ **measured unreliable** — negative result in §4 |
| Pre-register a "placeholder service" | Occupy the service name so installs return `ERROR_SERVICE_EXISTS` | Survived 90 s in testing | ⚠️ leaves a **fake service entry** on the system; bypassed if the installer deletes-then-creates; **and `sc create` itself carries a mis-creation risk, see 4.3** |
| Disable autostart via Autoruns | Turn off known autostart entries | GUI, broad coverage | ⚠️ covers **known** entries only; installers can create fresh ones |
| Security-software custom rules | Intercept via the security suite | Logs and alerts | ⚠️ requires GUI configuration; depends on that software |

**Selection logic**: the goal is "**make it unable to run without touching anyone's program files**" — hence IFEO is the first choice.

---

## 3. How IFEO works

### 3.1 What it is originally

When creating a process, the Windows kernel consults, **by image filename (no path)**:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<filename>
```

This is **the official mechanism for debuggers**: with a `Debugger` value written there, Windows launches that debugger instead and passes the original program as its argument (VS / WinDbg attach-debugging relies on it).

### 3.2 Turning it into a block

Since `Debugger` **replaces** the real launch target, pointing `Debugger` at a **nonexistent path** makes `CreateProcess` **fail outright** ("debugger program not found") — the target program is never executed.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AlibabaProtect.exe
    Debugger = C:\Windows\System32\BLOCKED-By-Admin-No-Exec.exe     ← path deliberately nonexistent
```

**Key properties**:

- **Global by image name** — wherever the file lives, however many copies exist, whatever path an update switches to, one rule covers all
- **Callers cannot bypass** — whoever initiates (client, scheduled task, double-click) is blocked at the `CreateProcess` layer
- **Zero file changes** — no file of the blocked program is touched
- **Seconds to revert** — delete the registry key and everything is restored

---

## 4. Measurements: verification results for three options

### 4.1 ⭐ IFEO — verified effective

**Reading the registry back is not verification** (it only proves "the value was written"); **functional verification is mandatory**. The method and full record are in [05-execution-forensics.en.md](05-execution-forensics.en.md); summary:

| Verification | Result |
|---|---|
| One-shot probe (`IFEO_PROBE_TEST.exe`), run before adding the block | ✅ Succeeded, `exit=0` |
| Same probe, run after adding the block | ✅ **`CreateProcess` failed: system cannot find the file specified** |
| Prefetch cross-check on real targets | ✅ No Prefetch record + `LastAccessTime` = trigger moment ⇒ attempted and blocked |
| The 4 production blocks after the probe cleanup | ✅ all intact; subkey count unchanged |

### 4.2 ❌ Negative result: Deny ACE on the service registry key — unreliable

A community approach: **take ownership of the service registry key, then add a Deny ACE for the `SYSTEM` account** (denying `SetValue` / `CreateSubKey` / `Delete` / `ChangePermissions` / `TakeOwnership`), reasoning that "the watchdog reverts configuration with SYSTEM privileges, so even SYSTEM must be denied".

**Measured conclusion: unreliable.**

| Step | Result |
|---|---|
| Create key + SYSTEM Deny ACE | ✅ `sc.exe create <name>` refused: `CreateService failed 5: access denied` |
| 90-second observation (**without** calling `sc create`) | ✅ Key and ACE survive stably |
| **After a failed `sc create` call** | ❌ **on the next check the key was gone** (reproduced 2 of 3 runs) |

**Inference**: **the Service Control Manager rolls back on `CreateService` failure, deleting the very key it was creating** — since the key was pre-created, the rollback deleted **our pre-placed blocker along with it**.

**Consequence**: the installer **destroys this defense on its very first attempt** and succeeds on the second. The defense is effectively useless.

### 4.3 ⚠️ Important warning about the "placeholder service" option

The "pre-register a placeholder service" row above (create a same-named service first so installs return `ERROR_SERVICE_EXISTS`) looks workable, **but its verification process itself has side effects — during testing it mis-created fake services**:

| Risk | Notes |
|---|---|
| **`sc create` syntax trap** | Parameter names like `binPath=` **must be followed by a space** (`binPath= "..."`; space after the equals sign). Writing `binPath="..."` parses it as part of the service name — **the service is still created**, just with wrong parameters |
| **Mis-created services must be cleaned immediately** | Once a fake service exists, **delete it at once**, or the system keeps a service entry pointing at a wrong path indefinitely |
| **On record** | Testing **twice created fake services pointing at `notepad.exe`** (experiment artifacts); cleaned and verified |

**Cleanup commands after a mis-creation**:

```cmd
:: First confirm the current state (were they actually created?)
sc.exe query AlibabaProtect
sc.exe query AliPaladin
reg query "HKLM\SYSTEM\CurrentControlSet\Services\AlibabaProtect"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\AliPaladin"

:: If they exist, delete immediately
sc.exe delete AlibabaProtect
sc.exe delete AliPaladin
```

**Standard for verified-clean**: all 4 commands return "service does not exist / key not found".

> ⚠️ **Recommendation: do not use the "placeholder service" option.** IFEO is measured-effective without these side effects; there is no reason to take on this risk. If you must try, **back up the registry first and run the verification above immediately after every experiment**.

### 4.4 ⚠️ Common failure: the write is intercepted by security software (measured)

**Symptom**: `--apply` or manual registry writes report:

```
PermissionError: [WinError 5] Access denied.
```

while **the current terminal is clearly admin** (`IsUserAnAdmin = True`).

**This is security software (HIPS) protecting writes to `Image File Execution Options`** — nothing to do with privileges.

#### How to confirm it's this

Run a contrast test — **an ordinary HKLM key is writable, an IFEO subkey is not**:

| Test target | Result (measured) | Meaning |
|---|---|---|
| Ordinary HKLM key (e.g. `SOFTWARE\<temp-name>`) | ✅ writable | privileges fine |
| **Creating a new subkey under IFEO** | ❌ **access denied** | ← protected |
| Writing values into an **existing** IFEO subkey | ✅ writable | protection covers "new subkeys" only |

**Note the last row**: the protection only blocks *creating* subkeys, so already-established blocks **are not** destroyed — but **adding/rebuilding** fails. This explains the seemingly contradictory "it worked before, suddenly fails now".

#### Remediation

| Option | Notes |
|---|---|
| Temporarily exit the security software, establish the blocks, then re-enable | Simplest; measured effective |
| Add an allow-rule in the security software's settings | More durable; location varies by product (usually "HIPS / custom rules / registry protection") |
| Use `reg.exe add` instead | **May** bypass (granularity varies by product), but should not be relied upon |

> **A reminder**: this kind of "registry protection" is a valuable feature (IFEO is a common persistence technique). **Do not leave it off because of this guide** — re-enable it after establishing the blocks.

> This repo's script **raises and aborts on write failure** — it never falsely reports success. If you see `[FAILED]`, troubleshoot per this section.

---

## 5. Limitations

| Limitation | Notes |
|---|---|
| **Filename matching** | Any program with that name gets blocked. Verify name uniqueness before enabling |
| **Cannot block a renamed installer** | But the core executables' names are typically stable — blocking them suffices |
| **Not a security boundary** | This is an **operational stability measure**, not an anti-attack mechanism; a privileged process can delete the registry key |
| **Terminology care** | IFEO is categorized as a persistence technique in attack taxonomies (MITRE ATT&CK **T1546.012**). This doc's use is **blocking specific programs from starting**, unrelated to attack scenarios; in public writing, **avoid words like "hijack/inject"** — use neutral phrasing such as "prevent the named image from launching" |
| **Requires admin** | Writing under `HKLM` |
| **May be reset by client updates** | Measured: client updates re-enable disabled scheduled tasks (`Disabled` → `Ready`) — re-disable as needed. The IFEO entries themselves were not cleared in testing, but that is not a guarantee |

---

## 6. A pragmatic combination

```
Layer 1: IFEO-block the 4 core executables (process / updater / checker / installer)
Layer 2: disable the related scheduled tasks (AliProctectUpdate / AliUpdater)
Layer 3: after every client update, re-check and reset whatever was changed
```

> Layer 3 is necessary — measured confirmation that client updates re-enable disabled tasks means **there is no "set once, effective forever" option**.

---

## 7. Commands and restoration

`scripts/ifeo_block.py` packages the above into reversible two-way commands:

```bash
# Establish the 4 blocks (admin required)
python scripts/ifeo_block.py --apply

# Show current status
python scripts/ifeo_block.py --status

# One-shot revert (removes only keys created by this script)
python scripts/ifeo_block.py --remove
```

The script **writes only registry keys under `Image File Execution Options`**, touching no client file; `--remove` deletes only keys targeting these image names and never removes existing system or third-party IFEO configuration.

**Fully manual restoration** (if you prefer no script):

```powershell
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($t in @('AlibabaProtect.exe','AliProtectUpdate.exe','AlibabaProtectCon.exe','pc-sdk-setup.exe')) {
    Remove-Item (Join-Path $ifeo $t) -Recurse -Force -ErrorAction SilentlyContinue
}
```

---

Prev: [05 · Execution-level forensics](05-execution-forensics.en.md)
