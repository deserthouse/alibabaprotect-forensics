# AlibabaProtect Forensics

**English** · [简体中文](README.md)

> **Note for non-expert readers**: this repo is a forensic record and does not need to be read end-to-end. If you simply noticed a process named `AlibabaProtect.exe` consuming resources and want it gone, go straight to the companion guide **[alibabaprotect-uninstall-guide](https://github.com/deserthouse/alibabaprotect-uninstall-guide)** — every step from read-only checks to cleanup verification, each with expected output. If the command line is unfamiliar, hand the guide's link to your AI assistant and have it walk you through, or execute for you; every step carries expected output to verify against.

[![License: MIT](https://img.shields.io/badge/License-MIT-0078D4.svg)](LICENSE)

**`AlibabaProtect` (display name `Alibaba PC Safe Service`) installs alongside Alibaba-family clients and runs as a resident `LocalSystem` service, measured at a sustained ~20% of one core; its companion driver was recorded installed 24 times in 70 days, and manual removal must follow a specific order or it gets rolled back. This repo documents the full forensics and verification.**

---

## What this is

**`AlibabaProtect` (display name `Alibaba PC Safe Service`, a background component installed alongside Alibaba-family clients) runs as an auto-start `LocalSystem` service and consumed a sustained ~20% of one core in measurement.**

This repo answers **what it is, on what evidence, and whether it is gone**; the hands-on steps live in the companion repo [alibabaprotect-uninstall-guide](https://github.com/deserthouse/alibabaprotect-uninstall-guide) — it answers **how to remove it**.

---

## Contents

- [What this is](#what-this-is)
- [Findings at a glance](#findings-at-a-glance)
- [Docs](#docs)
- [Scripts](#scripts)
- [Evidence and statement discipline](#evidence--statement-discipline)
- [Disclaimer](#disclaimer)

---

## Findings at a glance

| # | Finding | Evidence | Strength |
|:---:|---|---|:---:|
| 1 | It is a resident service `AlibabaProtect` (display name `Alibaba PC Safe Service`) running as **`LocalSystem`, `Start=2` (auto)** | Service registry export: `ImagePath` / `DisplayName` / `ObjectName` | ✅ measured |
| 2 | It ships a kernel driver `AliPaladinEx64.sys` (service `AliPaladin`) | Service registry export, driver PE metadata | ✅ measured |
| 3 | The driver registers **a file-system minifilter + a registry callback + a process-creation callback** | Embedded import/function names in the driver binary | ✅ measured (static capability ≠ actual interception) |
| 4 | It **repeatedly installs its own driver service** (multiple `7045` events for the same driver service) | System log, Service Control Manager | ✅ measured |
| 5 | After a crash, **SCM's recovery policy restarts it after 60 seconds** | System log `7031` verbatim | ✅ measured |
| 6 | In one measured session its **average CPU usage was ≈20% of one core** (÷16 logical processors ≈ 1.26% whole-machine) | Process sampling: cumulative CPU time ÷ uptime | ✅ measured (single machine, two sample points) |
| 7 | Its install directory contains **encrypted configuration files** and executables whose **Chinese strings are byte-transformed** | Binary static analysis | ✅ measured |
| 8 | What it actually does at runtime **cannot be asserted from static evidence** | Strings and config encrypted; no outbound connections measured | ⚠️ unproven (see 03) |

> Finding 8 is a deliberately kept blank. **"What it can do" and "what it is doing right now" are two different things**; this repo never writes the former as the latter.

---

## Docs

| Doc | What's in it |
|---|---|
| [01 · Component identity](docs/01-what-it-is.en.md) · [中文](docs/01-what-it-is.md) | Naming disambiguation (`AlibabaProtect` / `AliPaladin` / `aliedit` — don't conflate), component inventory, attribution methods |
| [02 · Behavior analysis](docs/02-behavior-analysis.en.md) · [中文](docs/02-behavior-analysis.md) | The self-protection trio, API capability enumeration, encrypted configuration, build traces |
| [03 · Resource cost](docs/03-resource-cost.en.md) · [中文](docs/03-resource-cost.md) | Measured data, metric definitions and conversion; an honest answer to "what does it do at high CPU" |
| [04 · Why it's hard to remove](docs/04-why-hard-to-remove.en.md) · [中文](docs/04-why-hard-to-remove.md) | Callback protection + SCM auto-recovery + client re-installation — three paths |
| [05 · Execution-level forensics](docs/05-execution-forensics.en.md) · [中文](docs/05-execution-forensics.md) | Proving interception works: Prefetch fingerprints + a one-shot probe experiment (full record) |
| [06 · Preventing recurrence](docs/06-prevent-recurrence.en.md) · [中文](docs/06-prevent-recurrence.md) | IFEO principles, option comparison, measured negative results and limitations |
| [evidence/](evidence/) | Sanitized raw evidence excerpts (registry exports, event logs, binary-analysis output) |
| [scripts/](scripts/) | Read-only diagnostic scripts |
| [DISCLAIMER.md](DISCLAIMER.md) | Scope statement and **AI usage statement** (bilingual) |

---

## Scripts

| Script | Purpose | Modifies system | Needs admin |
|---|---|---|---|
| `scripts/snapshot_before.py` | Pre-cleanup snapshot: services / processes / scheduled tasks / directories / drivers → archivable JSON + readable report | No (read-only) | No |
| `scripts/verify_clean.py` | Post-cleanup verification: five targets judged one by one, output `PASS / FAIL` | No (read-only) | No |
| `scripts/ifeo_block.py` | **Establish and one-shot revert** the IFEO interception (`--remove`) | **Yes** (reversible, registry only) | Yes |

```bash
# 1) Archive state before cleanup (recommended before touching anything)
python scripts/snapshot_before.py before.json

# 2) Verify after cleanup and reboot
python scripts/verify_clean.py

# 3) For anti-recurrence: establish the IFEO block / one-shot revert
python scripts/ifeo_block.py --apply
python scripts/ifeo_block.py --remove
```

`snapshot_before.py` and `verify_clean.py` are **read-only**; `ifeo_block.py` writes only registry keys under `Image File Execution Options`, fully reverts with `--remove`, and **never touches any client file**.

---

## Evidence and statement discipline

The writing of this repo follows four constraints, so readers can judge each conclusion's confidence:

1. **Every conclusion ships with reproducible evidence** — each judgment comes with a command, raw output, or a data table; no "as everyone knows" or "probably would".
2. **Capability vs. behavior are distinguished** — from binary strings one can infer "it **can** do X", not "it **is** doing X". They are documented in separate sections, with unproven items flagged in 03.
3. **Correlation vs. causation are distinguished** — temporal coincidence is only a lead. Such cases are always labeled "suspected correlation, unproven".
4. **Read-only first** — diagnostic scripts modify nothing; the only system-modifying script is `ifeo_block.py`, and it ships a revert path.

---

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md). In short:

- This documentation and the scripts are for **diagnosis and technical research on devices you own and administer** only.
- The author is **not affiliated** with any vendor mentioned, nor authorized or sponsored by them.
- Everything is based on **specific machines and versions**; other versions may differ in paths, versions, and behavior.
- The operations described may modify system services, drivers, and the registry — **assess and create a restore point first**.
- Do not use on other people's devices or in any unauthorized context.

## License

[MIT](LICENSE)
