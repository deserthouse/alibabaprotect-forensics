# 01 · Component Identity: Naming Disambiguation and Attribution

**English** · [简体中文](01-what-it-is.md)

When investigating resident components like this one, the first pitfall is not technical — it's the **names**. The same product uses different names across its service, driver, process, install directory, and scheduled tasks, making it easy to mistake different products for one, or one for several.

---

## 1. Naming disambiguation: three easily confused things

| Name | What it is | Relation to this repo |
|---|---|---|
| **`AlibabaProtect`** | **Service name**. Display name `Alibaba PC Safe Service`, process `AlibabaProtect.exe` | ⭐ **The subject of this repo** |
| **`AliPaladin`** | Service / display name of the **kernel driver**. File `AliPaladinEx64.sys` | ⭐ The driver bundled with the subject — the direct reason it "won't come clean" |
| `aliedit` (`pcas.exe` / `secbizsrv.exe` / `aliwssv.exe`) | **Alipay security control**, installed at `C:\Program Files (x86)\alipay\aliedit\` | ⚠️ **A completely different product** that happened to coexist on this machine — do not conflate |
| `AliWangWang` / Taobao desktop | Alibaba-family **clients** | One of them **reinstalls** `AlibabaProtect` on launch/update (see 04) |
| `AliProtectUpdate.exe` / `AlibabaProtectCon.exe` / `pc-sdk-setup.exe` | Updater / checker / installer | The interception targets of the anti-recurrence setup (see 06) |

> **The author's own misjudgment on record**: during the investigation, the `aliedit` services (`pcas`, `secbizsrv`) were briefly counted as evidence of "AlibabaProtect not fully removed". They are Alibaba-family components, but **belong to a different product** with a different remediation path.

---

## 2. The subject: the `AlibabaProtect` service

Registry export from the investigated machine (sanitized; full export in `evidence/service-AlibabaProtect.reg`):

| Field | Value |
|---|---|
| Service name | `AlibabaProtect` |
| **`DisplayName`** | **`Alibaba PC Safe Service`** |
| `ImagePath` | `"C:\Program Files (x86)\AlibabaProtect\1.0.70.3194\AlibabaProtect.exe"` |
| `Start` | `0x00000002` (**automatic**) |
| `ObjectName` | **`LocalSystem`** |

Key points:

- **`ImagePath` contains a version-numbered directory** (`1.0.70.3194`). Every update switches directories — path-based cleanup alone will miss files.
- Runs as `LocalSystem`, so it can load kernel drivers and modify its own service configuration.
- **The `DisplayName` is a "product name", not a technical identity** — what you see in the service list is `Alibaba PC Safe Service`, not `AlibabaProtect`. Searching services by product name often finds nothing.

### Install directory structure (measured)

```
C:\Program Files (x86)\AlibabaProtect\
    ├─ 1.0.70.2607\      ← old version, kept in full
    ├─ 1.0.70.2943\      ← old version, kept in full
    ├─ 1.0.70.3194\      ← currently running version
    └─ uninstallre.exe   ← uninstaller (1,844,784 bytes)
```

**Three version directories coexist**, each with 75–76 files — updates add a new directory rather than overwriting in place, and old versions are never auto-cleaned. This is the direct reason the footprint far exceeds expectations.

---

## 3. The driver: `AliPaladin`

| Field | Value |
|---|---|
| Service name / `DisplayName` | `AliPaladin` |
| `ImagePath` | `\??\C:\WINDOWS\system32\drivers\AliPaladinEx64.sys` |
| `Start` | `0x00000002` (automatic) |
| Observed state | Stopped (`Stopped / Auto`) — but the service entry exists, so it loads again on reboot |

### PE version info (**a key forensic surface**)

| Field | Value |
|---|---|
| `CompanyName` | `AliBaba Group` |
| `FileDescription` | `AliPaladin` |
| `FileVersion` | `1.19.4.1989` |
| **`OriginalFilename`** | **`AliPaladin.dll`** |
| File size | 177,880 bytes |

⭐ **The `OriginalFilename` says `.dll`, yet the file loads as `.sys`.** Vendors routinely forget to update this field when renaming or changing extensions — it indicates the driver **shares an origin with some user-mode DLL** or comes from the same project.

### Eight driver variants in the package

All present simultaneously in the install directory (measured):

```
AliPaladin.sys              AliPaladin64_win10.sys
AliPaladin_win10.sys        AliPaladin64_win7.sys
AliPaladin_win7.sys         AliPaladin64_win7_last.sys
AliPaladin_win7_last.sys    AliPaladinEx64.sys        ← the one actually loaded here
```

The same product ships one copy each for Win7 / Win10 / 32-bit / 64-bit. **This is why "delete the driver by filename" is unreliable** — the file you delete may not be the one currently loaded, and the updater restores the whole set anyway.

> Version numbers are inconsistent too: `AliPaladin_win7.sys` and `AliPaladin64_win7.sys` are `1.19.4.1909`, the rest `1.19.4.1989`. Match by version number with this discrepancy in mind.

> **Corroboration from a second machine (measured 2026-09, see `evidence/partial-cleanup-state.txt`)**: on another machine the `AliPaladin` service's `ImagePath` pointed to **`AliPaladin64.sys`** (again not the `Ex64` one), and its updater expected version directory **`1.0.70.988`** (previously unseen in the lineage). Driver variants and version directories **vary by machine/version** — detection and cleanup should read the actual values from the service registry entry at run time; hardcoding filenames or version numbers will miss.

---

## 4. Appendix: the other "capability components" in the package

The metadata of every executable in the install directory reveals the division of labor (for those with company/description fields present):

| File | Metadata clue | Role inferred from the name |
|---|---|---|
| `AlibabaProtect.exe` | No version resource (company/description empty) | Main process |
| `AntiDebug.dll` / `AntiInject.dll` | — | Anti-debug / anti-injection |
| `RestartService.exe` | — | Self-restart |
| `FileScanner.dll` / `FileWatch.dll` / `FileMonitor.dll` / `PathMon.dll` | — | File scanning / watching |
| `ProcessScanner.dll` | — | Process scanning |
| `Scheduler.dll` | — | Task scheduling |
| `Report.dll` / `ServiceReport.dll` / `ReportEnv.dll` / `EventTrack.dll` | — | Reporting and telemetry |
| `WebServer.dll` / `WebGate.dll` / `WebUnion.dll` / `NetCore.dll` | — | Local service / networking |
| `DBEngine.dll` | — | Local data (**embedded SQLite verified**: binary contains the `SQLite format 3` header and internal symbols like `sqlite_master`; see section 6 of `evidence/binary-strings-api-counts.txt`) |
| `SignVerify.dll` / `StrongBox.dll` / `DataEnc.dll` | — | Signature verification / encryption |
| `SecurityGuardSDK(64).dll` / `ThreatSieveSDK(64).dll` | — | Security SDKs |
| `AbstractM.dll` | — | Version abstraction layer |
| `msvcp120.dll` / `msvcr120.dll` | Version string contains **`built by: REL AliSec`** | Self-compiled VC runtime (not the original Microsoft build) |
| `perfmonsdk.dll` | `Alibaba Group` / `Perfmon` / `1.2.68` | Performance-monitoring SDK |
| `BluePerfmon4_*.sys` (6 variants) | **`Windows (R) Win 7 DDK provider`** / `Blue Perfmon Driver` / `1.0.1.5` | Yet another kernel driver; the signer string is an **old-DDK placeholder** |
| `arphadump.dll` / `arphaCrashReport.exe` | `2.2.66` / `Alibaba Group` | Crash collection |
| `courgette.dll` | — | Binary differential update (a Chromium project component) |

Three points worth noting:

1. **`msvcp120.dll` / `msvcr120.dll` carry `built by: REL AliSec`** — a runtime **compiled by Alibaba's security team**, not the Microsoft original. Same-named DLLs also exist in the system directory; they are not the same files.
2. **`BluePerfmon4_*.sys`'s signer string is `Windows (R) Win 7 DDK provider`** — a **typical placeholder string of old-DDK build output**, not a company name. Seeing it means "built with an old DDK", not "from Microsoft".
3. `courgette.dll` in the install directory indicates the update mechanism uses **binary differencing** (downloading only deltas), which also explains frequent updates with small size growth.

> ⚠️ The right column above is **roles inferred from filenames and metadata** — leads, not conclusions. Filenames are weaker evidence than the API evidence in doc 02; treat the two separately.

---

## 5. The attribution methods used in this doc

| Means | Command | What it reveals |
|---|---|---|
| Service registry | `reg export` / `reg query "HKLM\SYSTEM\CurrentControlSet\Services\<name>"` | Service name / **display name** / `ImagePath` / `Start` / run-as account |
| PE version info | `(Get-Item x.exe).VersionInfo \| fl CompanyName,FileDescription,FileVersion,**OriginalFilename**` | Company / description / version / **original filename** (the field most likely to reveal the truth) |
| Embedded function names | Direct ASCII string search (standard static analysis) | Which system mechanisms it calls/registers (see 02) |
| Service install history | System log event `7045` | When installed, and how many times (see 04) |

**Core principle: never judge what a component is by its name.** Names are products of marketing; `OriginalFilename`, embedded function names, and registered callback types are the technical identity.

---

Next: [02 · Behavior analysis](02-behavior-analysis.en.md) — which system mechanisms these components actually register.
