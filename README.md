# AlibabaProtect 取证

**Windows 上 `AlibabaProtect`（显示名 `Alibaba PC Safe Service`）的组件身份、行为证据、资源开销、难卸载机制与清理验证**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 这个仓库是什么

一台 Windows 机器上出现了**卸载了阿里系客户端之后仍然常驻、且消耗可观 CPU 的 `AlibabaProtect.exe`**。本仓库把这台机器上采集到的证据、可复现的判定方法和每一步的验证结果整理成文档。

**只讲 `AlibabaProtect` 这一个组件。** 不含通用内存分析、不含其他厂商组件、不含与本组件无关的系统调优内容。

配套的操作步骤在另一个仓库：[alibabaprotect-uninstall-guide](https://github.com/deserthouse/alibabaprotect-uninstall-guide)。本仓库回答「**它是什么、凭什么这么判断、删干净了没有**」，指南仓库回答「**怎么删**」。

---

## 实测结论摘要

| # | 结论 | 证据 | 强度 |
|---|---|---|---|
| 1 | 它是一个**以 `LocalSystem` 运行、`Start=2`（自动）** 的常驻服务 `AlibabaProtect`，显示名 `Alibaba PC Safe Service` | 服务注册表导出：`ImagePath` / `DisplayName` / `ObjectName` | **确定** |
| 2 | 它配备内核驱动 `AliPaladinEx64.sys`（服务名 `AliPaladin`，显示名同名） | 服务注册表导出、驱动文件 PE 元数据 | **确定** |
| 3 | 该驱动同时注册**文件系统微过滤器 + 注册表回调 + 进程创建回调** | 驱动二进制内嵌导入/函数名 | **确定**（静态能力） |
| 4 | 它会**重复自行安装驱动服务**（同一驱动服务被记录到多次 `7045` 事件） | 系统日志 `Service Control Manager` | **确定** |
| 5 | 服务崩溃后 **SCM 恢复策略会在 60 秒后自动重启它** | 系统日志 `7031` 原文 | **确定** |
| 6 | 在本机一次实测中，它的**累计 CPU 时间 ≈ 20% 单核**（折算 ≈1.25% 整机 / 16 逻辑处理器） | 进程采样：累计 CPU 时间 ÷ 运行时长 | **确定**（单机数据） |
| 7 | 它的安装目录内含**加密的配置文件**与**中文字符串被逐字节变换**的可执行体 | 二进制静态分析 | **确定** |
| 8 | 它在运行时**具体在做什么** —— 无法从静态证据断言 | 字符串与配置加密，且本机实测无外连 | **未证实**（见 03） |

> 第 8 条是有意保留的空白。**"它能做什么"与"它此刻在做什么"是两件事**，本仓库不把前者当后者写。

---

## 目录

| 文档 | 内容 |
|---|---|
| [docs/01-what-it-is.md](docs/01-what-it-is.md) | **它是谁**：命名辨析（`AlibabaProtect` / `AliPaladin` / `aliedit` 不要混淆）、组件清单、身份鉴定的方法 |
| [docs/02-behavior-analysis.md](docs/02-behavior-analysis.md) | **它有什么能力**：自保护三件套、API 能力枚举、加密配置、构建痕迹 |
| [docs/03-resource-cost.md](docs/03-resource-cost.md) | **它占多少资源**：实测数据、指标口径与折算方法；以及"CPU 高时在干什么"的诚实回答 |
| [docs/04-why-hard-to-remove.md](docs/04-why-hard-to-remove.md) | **为什么删不干净**：回调保护 + SCM 自动恢复 + 客户端重装三条路径 |
| [docs/05-execution-forensics.md](docs/05-execution-forensics.md) | **怎么证明"拦住了"**：Prefetch 指纹 + 一次性探针实验（含完整实验记录） |
| [docs/06-prevent-recurrence.md](docs/06-prevent-recurrence.md) | **防复发**：IFEO 原理、方案对比、实测负面结果与局限 |
| [evidence/](evidence/) | **脱敏后的原始证据摘录**（注册表导出、事件日志、二进制分析输出） |
| [scripts/](scripts/) | 只读诊断脚本 |
| [DISCLAIMER.md](DISCLAIMER.md) | 使用范围声明 |

---

## 脚本

| 脚本 | 用途 | 是否修改系统 | 需要管理员 |
|---|---|---|---|
| `scripts/snapshot_before.py` | 清理前状态快照：服务 / 进程 / 计划任务 / 目录 / 驱动，输出可存档的 JSON + 可读报告 | 否（只读） | 否 |
| `scripts/verify_clean.py` | 清理后核验：五项目标逐条判定，输出 `通过 / 未通过` | 否（只读） | 否 |
| `scripts/ifeo_block.py` | IFEO 拦截的**建立与一键还原**（`--remove`） | **是**（可逆，仅注册表） | 是 |

```bash
# 1) 清理前留档（建议在动任何东西之前先跑）
python scripts/snapshot_before.py before.json

# 2) 清理并重启后核验
python scripts/verify_clean.py

# 3) 需要防复发时：建立 IFEO 拦截 / 一键还原
python scripts/ifeo_block.py --apply
python scripts/ifeo_block.py --remove
```

`snapshot_before.py` 与 `verify_clean.py` **只读**；`ifeo_block.py` 只写 `Image File Execution Options` 下的注册表键，`--remove` 可完整还原，且**不触碰任何客户端文件**。

---

## 证据与表述原则

本仓库的写法遵循四条约束，读者可以据此判断每条结论的可信度：

1. **结论必须带可复现的证据** —— 每个判断附命令、原始输出或数据表；不写"众所周知""大概会"。
2. **区分「能力」与「行为」** —— 从二进制字符串能推出"它**能**做 X"，不等于"它**正在**做 X"。两者分节表述，并在 03 明确标注未证实项。
3. **区分「关联」与「因果」** —— 时间上吻合只是线索。文档中把此类情形一律标为"疑似相关，未证实"。
4. **只读优先** —— 诊断脚本不修改系统；会修改系统的只有 `ifeo_block.py`，且给出还原路径。

---

## 免责声明

详见 [DISCLAIMER.md](DISCLAIMER.md)。简要版：

- 本文档与脚本仅供**在你自己拥有并管理的设备上**进行诊断与技术研究。
- 作者与文中提及的任何厂商**均无关联**，也未获其授权或赞助。
- 文档基于**特定机器与特定版本**的实测记录；不同版本的路径、版本号、行为可能不同。
- 文中涉及的操作可能修改系统服务、驱动与注册表，**执行前请自行评估并创建还原点**。
- 请勿用于他人设备或任何未经授权的场景。

## License

[MIT](LICENSE)
