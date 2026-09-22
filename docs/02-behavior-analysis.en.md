# 02 · Behavior Analysis: Which Mechanisms It Registers, What It Can Do

**English** · [简体中文](02-behavior-analysis.md)

Everything in this doc comes from **static analysis of archived binaries** (read-only). It therefore answers "**what it can do**", not "**what it is doing right now**".

---

## 1. Core mechanisms: the self-protection trio (driver `AliPaladinEx64.sys`)

The following system-routine names were found by direct search in the driver binary (raw output in `evidence/driver-AliPaladin-functions.txt`):

| Embedded function | Meaning | Direct effect |
|---|---|---|
| `FltRegisterFilter` | Registers a **file-system minifilter** | Can intercept/permit file operations → **protects its own install directory**; deletes fail with `Access denied` |
| `FltStartFiltering` | **Starts** the filter above | Completes the filter lifecycle together with the previous entry |
| `CmRegisterCallback` | Registers a **registry callback** | Can intercept registry writes → consistent with the observed **"`Start` reverted from `disabled` to `auto` within seconds"** (see doc 04 §2; the reverting agent was not traced — this is a **mechanism inference**; a user-mode process polling and writing back is also possible) |
| `PsSetCreateProcessNotifyRoutine` | Registers a **process-creation callback** | Can observe process creation/exit → **guards `AlibabaProtect.exe` itself** |
| `KeStackAttachProcess` | **Cross-process memory operations** | Can read/write other processes' address spaces |
| `IoCreateDevice` | Creates a device object | Provides the **user-mode communication interface** |

File size: 177,880 bytes.

**This is the complete technical explanation of "why normal methods can't stop it"**: three callbacks, one per front — files (can't delete), registry (can't disable), processes (can't kill). All three are registered by the same driver, so **as long as the driver keeps loading, cleanup gets rolled back**.

> Distinguish carefully: `FltRegisterFilter` shows it **can** intercept file operations, not that it **is** intercepting all of them. The filter's actual rules need further evidence (INF altitude values, behavioral observation).

### 1.1 Independent second evidence: the minifilter configuration on the registry side

The "minifilter" conclusion above comes from **code strings inside the driver binary**. In the **service registry entry** there is a fully independent set of fields pointing to the same conclusion (measured values in `evidence/service-AliPaladin-minifilter.txt`):

| Field | Measured value | What it shows |
|---|---|---|
| `Group` | **`FSFilter Activity Monitor`** | `FSFilter` is the service group Windows reserves for **file-system filter drivers**; the `Activity Monitor` subgroup sits at the very top of the load-order chain |
| `Altitude` | **`265109`** | A minifilter's **unique slot number**, fixing its exact position in the filter stack; this value falls within Microsoft's reserved range for the "activity monitor" class |
| `DependOnService` | **`FltMgr`** | Depends on the **Filter Manager** — a loading mechanism specific to minifilters; ordinary kernel drivers don't depend on it |
| `Type` / `Start` | `2` / `2` | Kernel driver / auto start |

**The two evidence sets agree**:

```
Code side (function names in .sys)     Registry side (service config)
──────────────────────────────         ────────────────────────────────
FltRegisterFilter                      Group = FSFilter Activity Monitor
FltStartFiltering                      Altitude = 265109
                                       DependOnService = FltMgr
```

⇒ It is a file-system minifilter **actually configured with a slot and loaded by the system** — not a hollow capability that exists in code but is never enabled. This directly explains the observed **`Access denied` when deleting the install directory**.

---

## 2. The user-mode communication interface

| Observation | Value |
|---|---|
| Device name exported by the driver | **`\\.\CtrlSM`** |
| Driver-communication API hits | 24 (`CreateFileW` / `DeviceIoControl` / `NtDeviceIoControlFile`, etc.) |

`\\.\CtrlSM` is the **control channel** between `AlibabaProtect.exe` and the kernel driver. The name `CtrlSM` (Control State Machine or similar) has no relation to the product name — yet another case of "don't judge by the name".

**Practical use**: this device name can confirm "is the driver working". When the driver is not loaded, opening the device fails.

---

## 3. API capability enumeration

String scan across the main executable modules in the install directory (27 targets, 26 hit), API names grouped by category (**certificate-chain noise such as DigiCert removed**):

| Category | Hits | Notes |
|---|---|---|
| **Enumeration APIs** | **61** | `SetupDi*` / `CM_*` / `EnumProcess*` / `CreateToolhelp32Snapshot` / `WTSEnumerate*` / `NetServerEnum` / `RegEnum*` / `FindFirstFile*` — enumeration capability over **devices, processes, sessions, network resources, registry, files** |
| **Network/reporting APIs** | **108** | `WinHttp*` / `InternetOpen*` / `HttpSend*` / `getaddrinfo` / `WSAStartup`, etc. |
| **Process/memory APIs** | **93** | `OpenProcess` / `ReadProcessMemory` / `Module32*` / `GetModuleFileName*` / `QueryFullProcessImageName*` / `ZwQuery*` |
| HTTP headers / Content-Type literals | 31 | `Content-Type` / `application/json` / `application/x-www-form-urlencoded` |
| Device / enumeration interface paths | 26 | Device names beginning `\\.\` |
| **Plaintext API paths (`/api/...`)** | **0** | See finding 1 below |
| Plaintext full URLs | **1** | And it is a third-party website link |

### Finding 1: **no plaintext reporting endpoint**

Interface paths like `/report`, `/collect`, `/upload` that one would expect — **none present**. Yet `WinHttp*` calls number 108.

⇒ The only possible conclusion: **the reporting address is not stored in plaintext in the binary**. It may come from the encrypted configuration (see §4), be delivered at runtime, or be string-encrypted. **This is not an accusation — it only means "static analysis cannot see its communication targets"**, which is exactly the boundary stated in §5.

### Finding 2: the only plaintext URL is a technical-forum link

The single "full URL" string hit was:

```
https://reverseengineering.stackexchange.com/questions/14171/thread-local-storage-access-on-...
   ← from perfmonsdk.dll
```

A **reverse-engineering forum** link inside `perfmonsdk.dll` (the performance-monitoring SDK, `1.2.68`), pointing to a discussion of thread-local storage access.

Two readings, **neither pointing to malice**:

1. A developer copied a code snippet from the forum into the project, **link in the comment and all**;
2. The SDK incorporates a piece of public code, and the link is the attribution.

Either way, `perfmonsdk.dll` is **at least partly based on public/third-party code** — contrary to the intuition of it being a fully in-house SDK. The forensic conclusion to record: **this module's code is not entirely in-house; traces of public-code reuse exist**.

---

## 4. Configuration and strings are obfuscated

### 4.1 The `.dat` configuration files are not text

| File | Size | First 16 bytes |
|---|---|---|
| `AlibabaProtect.dat` | 942 B | `ff 10 10 ff 01 00 01 00 01 00 00 00 1e 03 00 00 ...` |
| `AlibabaProtectEx.dat` | 1,328 B | `ff 10 10 ff 01 00 01 00 01 00 00 00 a0 04 00 00 ...` |

Decoding attempts with `utf-8` / `utf-16-le` / `gbk`: **all non-text**.

Further observation: the two files share the same header structure (`ff1010ff` magic + identical field region), followed by a run with an **obvious linear increment pattern**:

```
... 00 84 08 8c 10 94 18 9c 20 a4 28 ac 2f b3 37 bb 3f c3 47 cb 4f d3 57 db 5f e2 66 ea 6e f2 76 fa 7e 02 86 ...
       ↑ each entry +8, with periodic high-bit carry
```

An **equal-stride increment** like this is characteristic of **bitwise operations or a simple key transform** (per-byte XOR / add-subtract), not strong encryption (strong encryption output approximates randomness).

⇒ Conclusion: **the configuration is stored under a lightweight transform**. In other words, **even its own vendor did not consider this content something to be read casually**.

> **What was not done, deliberately**: this repo does not decrypt, and provides no decryption method. Recording the fact that "the content is transformed" satisfies the forensic purpose.

### 4.2 Chinese strings are transformed byte-by-byte

Extracting Chinese strings from the main process and DLLs yields **mostly unreadable mojibake**, e.g.:

```
佩赃耪魊 琵云耪魖
琵云琵ot$`排鬸勁踉团鹏zづ碓着汪j勁逶菖汪zづ菰缗汪jD琵耘琵o
砰哉派魖@篷韵霹ol$0派魊0霹云叛魖
```

These characters are **not random** — they show a highly consistent structure, indicating the original text is Chinese, merely offset byte-wise.

**Meanwhile, two strings "escaped" and remain readable plaintext**:

```
无法查询版本信息: 
无法获取当前进程的模块文件名: 
```

These are **error-message strings** the vendor left untransformed. They happen to leak two operations:

| Plaintext remnant | Operation inferred |
|---|---|
| `无法查询版本信息: ` ("failed to query version info") | It **queries version information** |
| `无法获取当前进程的模块文件名: ` ("failed to get current process module filename") | It **obtains the current process's module filename** |

The second is especially worth recording: **a resident service obtaining "the current process's module filename" is a classic self-verification/self-identification action** (checking "is the thing running one of my own copies?").

> These two are **the only behavioral leads directly observed in this static analysis** — from escaped plaintext, not from decryption.

---

## 5. Boundary of conclusions: capability ≠ behavior

This section must draw one line clearly, or the "capability list" gets read as a "charge sheet".

| Proven (**capability**) | Not proven (**behavior**) |
|---|---|
| The driver registers file/registry/process callbacks | Which files and registry keys it **actually** intercepts |
| Full device/process/network/registry enumeration capability | What it **actually** enumerates, and how often |
| The complete API stack needed for network reporting | Where it **actually** sends what data (measured on this machine: **no TCP connections**) |
| It obtains the current process's module name; it queries version info | What decisions it makes with that information |
| Configuration and strings are stored transformed | What the transform algorithm is; what the configuration contains |

**Between what it can do and what it is doing lies a gap of measured evidence.** This repo writes the left column into tables and deliberately leaves the right one blank.

---

## 6. Build traces

| Clue | Value | Meaning |
|---|---|---|
| PDB / build path | `C:\jenkins\workspace\pc-sdk-build\...` | Built by **Jenkins** CI, project name **`pc-sdk-build`** ("PC SDK build") |
| VC runtime version string | `built by: REL AliSec` | msvcp120/msvcr120 **compiled by Alibaba's security team** themselves |
| Project name matches the installer | The installer in the client directory is **`pc-sdk-setup.exe`** (~37 MB) | Matches the CI project `pc-sdk-build` — **confirming this installer is that CI project's product** |

**The CI project name is a high-value clue**: it ties the scattered files (`pc-sdk-setup.exe`, the driver, the DLLs) into one production line, and explains "why it comes back after uninstalling the client" — the client's update flow includes an installation step for this SDK.

---

## 7. Limitations of static analysis

| Limitation | Consequence |
|---|---|
| Chinese strings and `.dat` are transformed | **No functional descriptions, configuration contents, or reporting addresses obtainable** |
| No disassembly, no dynamic debugging | **Control flow and decision logic undetermined** |
| No packet capture, no IOCTL semantics | **The command semantics of `\\.\CtrlSM` undetermined** |
| No integrity verification beyond signature checks | Cannot rule out "downloads and executes additional code at runtime" (measured: no connections on this machine, but the sample is limited) |

**Conclusion: static analysis can state clearly "what mechanisms it registered" but not "what it intends to do".** This repo does not overreach.

---

Prev: [01 · Component identity](01-what-it-is.en.md) ｜ Next: [03 · Resource-cost measurements](03-resource-cost.en.md)
