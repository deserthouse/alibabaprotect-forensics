# 使用范围声明 / Intended Use Statement

## 中文

### 本文档与其中提及的工具的用途

本项目记录的是**对 `AlibabaProtect` 这一个 Windows 常驻组件的诊断与技术研究**，目标读者是**在自己拥有并管理的设备上进行排障的技术人员**。

### 脚本

`scripts/` 目录下的脚本分两类，**在 README 与脚本自身的 `--help` 中都明确标注**：

| 脚本 | 行为 |
|---|---|
| `snapshot_before.py` / `verify_clean.py` | **只读**。仅调用系统查询接口读取服务、进程、计划任务、目录信息 |
| `ifeo_block.py` | **会写入注册表**（仅 `Image File Execution Options` 下的键）。`--remove` 可完整还原 |

**没有任何脚本会**：修改或删除任何程序的安装文件、卸载软件、修改服务配置、联网上传数据。

### 文档中提及的处置步骤

文档中描述的手工处置步骤（禁用计划任务、删除服务注册项、删除目录、IFEO 等）**会修改系统配置**。执行前请自行评估，并建议先创建系统还原点与注册表备份。

### 立场与关联

- 作者与本文档中提及的任何厂商**均无关联**，也未获其授权、赞助或认可。
- 文中出现的产品名、服务名、文件名**仅用于客观指称**（用于定位与描述所讨论的技术对象）。
- 本文档**不提供**任何二进制、安装包或编译产物；**不提供 Release**。
- 本文档的目标是**技术分析与排障方法**，不是提供规避安全软件的方案。
- `evidence/` 中的内容均为作者本机采集的**客观事实记录**（服务配置、文件路径、符号名、日志摘录等），不含任何厂商代码、二进制或受版权保护的本体资源。
- 本项目仅记录**终端用户对自有设备的管理权**的行使；不主张、也不协助对他人计算机系统或厂商线上服务的任何操作。
- 文中的资源消耗数据为**单机实测**，不代表其他环境。

### 表述纪律

本项目的分析**刻意区分**以下三类陈述，请在阅读时一并注意：

| 类型 | 例子 | 强度 |
|---|---|---|
| **实测事实** | "该服务在 2026-07-11 至 09-18 间被记录了 24 次安装" | 可直接引用 |
| **能力推断** | "该驱动注册了注册表回调（由其内嵌符号判定）" | 说明它**能**做什么，不代表此刻在做 |
| **疑似关联** | "该事件连续三次出现在崩溃重启后的约 20 秒" | **线索，不是结论** |

**特别声明**：本项目**不主张**该组件存在恶意行为。文中列出的"能力清单"来自静态分析（字符串与 API 名），
它证明的是**代码具备这些能力**，而不是"它正在做某事"。凡未获直接证据的部分，文中均标注为**未证实**。

### AI 使用声明

本项目的研究、取证与文档撰写**深度参与使用了 AI 工具**（代码辅助与文本整理），但：

- 全部**研究目标、清理决策与最终验收由人类作者作出**；
- 所有证据均采集自作者本人设备，采集命令与原始输出可在 `evidence/` 复核；
- 文档结论由人类作者审订后发布，表述纪律（实测事实 / 能力推断 / 疑似关联）由人类作者把关。

### 免责

本项目以 MIT 许可发布，**不提供任何明示或暗示的担保**。因使用本文档或脚本而产生的任何后果，由使用者自行承担。

---

## English

### Purpose

This project documents **diagnostic work and technical research on one specific Windows resident component (`AlibabaProtect`)**,
intended for technicians troubleshooting **systems they own and administer**.

### Scripts

Scripts under `scripts/` fall into two categories, **labeled in the README and in each script's own `--help`**:

| Script | Behavior |
|---|---|
| `snapshot_before.py` / `verify_clean.py` | **Read-only.** Query services, processes, scheduled tasks, and directories |
| `ifeo_block.py` | **Writes to the registry** (only keys under `Image File Execution Options`). Fully reverted by `--remove` |

**No script** modifies or deletes any program's installed files, uninstalls software, changes service configuration, or uploads data.

### Remediation steps in the docs

Manual remediation steps described in the documentation (disabling scheduled tasks, deleting service entries,
removing directories, IFEO) **modify system configuration**. Evaluate them yourself and create a restore point and
registry backup first.

### Affiliation and scope

- The author is **not affiliated with, endorsed by, or sponsored by** any vendor mentioned.
- Product, service, and file names appear **solely for nominative reference**, to identify the technical subject under discussion.
- This project ships **no binaries, installers, or compiled artifacts**, and publishes **no releases**.
- The intent is **analysis and troubleshooting methodology**, not circumventing security software.
- Everything in `evidence/` is a **factual record collected from the author's own machines** (service configurations, file paths, symbol names, log excerpts); the project contains **no vendor code, binaries, or copyrighted original resources**.
- This project documents only the exercise of an **end user's right to administer their own devices**; it does not claim, nor assist, any operation against other people's computer systems or the vendor's online services.
- Resource-consumption figures are **single-machine measurements** and do not represent other environments.

### Statement discipline

| Type | Example | Strength |
|---|---|---|
| **Measured fact** | "the service was recorded as installed 24 times" | citable |
| **Capability inference** | "the driver registers a registry callback (from its embedded symbols)" | says what it *can* do, not what it is doing now |
| **Suspected correlation** | "the event appeared ~20 s after each of three boots" | a lead, not a conclusion |

**Explicit statement**: this project does **not** allege malicious behavior.
The "capability" lists come from static analysis (strings and API names); they show what the code *can* do,
not what it is doing. Anything without direct evidence is marked **unconfirmed**.

### AI Usage Statement

AI tools were **substantially involved** in the research, forensic analysis, and drafting of this project
(code assistance and text organization). However:

- All **research goals, cleanup decisions, and final acceptance were made by the human author**;
- All evidence was collected from the author's own machines; collection commands and raw output can be
  re-checked in `evidence/`;
- Conclusions were reviewed and finalized by the human author before publication, including the statement
  discipline (measured fact / capability inference / suspected correlation).

### Disclaimer

Released under the MIT License, **without warranty of any kind**. Any consequences of use are the user's own.
