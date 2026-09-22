# 01 · 组件身份：命名辨析与鉴定

**简体中文** · [English](01-what-it-is.en.md)

排查这类驻留组件时，首先遇到的易错点不是技术，是**名字**：同一个产品在服务、驱动、进程、安装目录、计划任务里使用多个不同名字，很容易把不同产品当成同一个，或把同一个当成多个。

---

## 1. 命名辨析：三个容易混淆的东西

| 名字 | 它是什么 | 与本次的关系 |
|---|---|---|
| **`AlibabaProtect`** | **服务名**。显示名 `Alibaba PC Safe Service`，进程 `AlibabaProtect.exe` | ⭐ **本仓库的主体** |
| **`AliPaladin`** | **内核驱动**的服务名 / 显示名。文件 `AliPaladinEx64.sys` | ⭐ 主体**配备的驱动**，是"删不干净"的直接原因 |
| `aliedit`（`pcas.exe` / `secbizsrv.exe` / `aliwssv.exe`） | **支付宝安全控件**，装在 `C:\Program Files (x86)\alipay\aliedit\` | ⚠️ **完全不同的产品**，恰好同机存在，不要混为一谈 |
| `AliWangWang` / `淘宝桌面版` | 阿里系**客户端** | 二者之一会在启动/更新时**重新安装** `AlibabaProtect`（见 04） |
| `AliProtectUpdate.exe` / `AlibabaProtectCon.exe` / `pc-sdk-setup.exe` | 更新器 / 检查器 / 安装包 | 防复发的拦截对象（见 06） |

> **作者本人的误判记录**：排查中一度把 `aliedit` 的服务（`pcas`、`secbizsrv`）也算进"AlibabaProtect 没能删干净"的证据里。它们确实是阿里系组件，但**属于另一个产品**，两者的处置路径不同。

---

## 2. 主体：`AlibabaProtect` 服务

实测机器上的注册表导出（已脱敏，完整导出见 `evidence/service-AlibabaProtect.reg`）：

| 字段 | 值 |
|---|---|
| 服务名 | `AlibabaProtect` |
| **`DisplayName`** | **`Alibaba PC Safe Service`** |
| `ImagePath` | `"C:\Program Files (x86)\AlibabaProtect\1.0.70.3194\AlibabaProtect.exe"` |
| `Start` | `0x00000002`（**自动**） |
| `ObjectName` | **`LocalSystem`** |

要点：

- **`ImagePath` 里带版本号目录**（`1.0.70.3194`）。这意味着**每次更新换目录**，只按路径清理会漏。
- 以 `LocalSystem` 运行，因此它能加载内核驱动、能改自己的服务配置。
- **`DisplayName` 是"产品名"，不是技术身份** —— 在服务列表里看到的是 `Alibaba PC Safe Service`，不是 `AlibabaProtect`。找服务时用显示名搜常常搜不到。

### 安装目录结构（实测）

```
C:\Program Files (x86)\AlibabaProtect\
    ├─ 1.0.70.2607\      ← 旧版本，整体保留未删
    ├─ 1.0.70.2943\      ← 旧版本，整体保留未删
    ├─ 1.0.70.3194\      ← 当前运行版本
    └─ uninstallre.exe   ← 卸载器（1,844,784 字节）
```

**三个版本目录并存**，各自 75–76 个文件 —— 说明更新是"新增目录"而非"原地覆盖"，旧版本不会被自动清理。这是它体积远超预期的直接原因。

---

## 3. 驱动：`AliPaladin`

| 字段 | 值 |
|---|---|
| 服务名 / `DisplayName` | `AliPaladin` |
| `ImagePath` | `\??\C:\WINDOWS\system32\drivers\AliPaladinEx64.sys` |
| `Start` | `0x00000002`（自动） |
| 实测状态 | 已停止（`Stopped / Auto`）——但服务注册项存在，重启仍会加载 |

### PE 版本信息（**关键取证面**）

| 字段 | 值 |
|---|---|
| `CompanyName` | `AliBaba Group` |
| `FileDescription` | `AliPaladin` |
| `FileVersion` | `1.19.4.1989` |
| **`OriginalFilename`** | **`AliPaladin.dll`** |
| 文件大小 | 177,880 字节 |

⭐ **`OriginalFilename` 写的是 `.dll`，而它实际以 `.sys` 形态加载。** 这一栏厂商改名/改扩展名时经常忘了改 —— 它说明这个驱动与某个用户态 DLL **同源或由同一个工程产出**。

### 包里一共 8 个驱动变体

安装目录中同时存在（实测）：

```
AliPaladin.sys              AliPaladin64_win10.sys
AliPaladin_win10.sys        AliPaladin64_win7.sys
AliPaladin_win7.sys         AliPaladin64_win7_last.sys
AliPaladin_win7_last.sys    AliPaladinEx64.sys        ← 本机实际加载的这个
```

同一份产物为 Win7 / Win10 / 32 位 / 64 位各准备一份。**这解释了为什么"按文件名删驱动"不可靠** —— 你删掉的可能不是当前系统加载的那个，而更新器会把整组再放回来。

> 版本号也不一致：`AliPaladin_win7.sys` 与 `AliPaladin64_win7.sys` 是 `1.19.4.1909`，其余为 `1.19.4.1989`。以版本号为线索做匹配时要注意这个差异。

> **第二台机器印证（2026-09 实测，见 `evidence/partial-cleanup-state.txt`）**：另一台机器上 `AliPaladin` 服务键的 `ImagePath` 指向的是 **`AliPaladin64.sys`**（同样不是 `Ex64` 那个），其更新器期望的版本目录为 **`1.0.70.988`**（此前未见于版本谱系）。驱动变体与版本目录**因机器/版本而异**——清理与检测都应从服务注册项现取实际值，按固定文件名/版本号写死会漏。

---

## 4. 附：包里还有这些"能力组件"

从安装目录的全部可执行文件元数据里能读出各组件的**分工**（公司/描述字段完整的部分）：

| 文件 | 元数据线索 | 从名字可推测的角色 |
|---|---|---|
| `AlibabaProtect.exe` | 无版本资源（公司/描述为空） | 主进程 |
| `AntiDebug.dll` / `AntiInject.dll` | — | 反调试 / 反注入 |
| `RestartService.exe` | — | 自我重启 |
| `FileScanner.dll` / `FileWatch.dll` / `FileMonitor.dll` / `PathMon.dll` | — | 文件扫描 / 监视 |
| `ProcessScanner.dll` | — | 进程扫描 |
| `Scheduler.dll` | — | 任务调度 |
| `Report.dll` / `ServiceReport.dll` / `ReportEnv.dll` / `EventTrack.dll` | — | 上报与埋点 |
| `WebServer.dll` / `WebGate.dll` / `WebUnion.dll` / `NetCore.dll` | — | 本地服务 / 网络 |
| `DBEngine.dll` | — | 本地数据（**已核验内嵌 SQLite**：二进制含 `SQLite format 3` 头与 `sqlite_master` 等内部符号，见 `evidence/binary-strings-api-counts.txt` 第六节） |
| `SignVerify.dll` / `StrongBox.dll` / `DataEnc.dll` | — | 签名校验 / 加密 |
| `SecurityGuardSDK(64).dll` / `ThreatSieveSDK(64).dll` | — | 安全 SDK |
| `AbstractM.dll` | — | 版本抽象层 |
| `msvcp120.dll` / `msvcr120.dll` | 版本串含 **`built by: REL AliSec`** | 自编译的 VC 运行时（不是原版 Microsoft 版本） |
| `perfmonsdk.dll` | `Alibaba Group` / `Perfmon` / `1.2.68` | 性能监控 SDK |
| `BluePerfmon4_*.sys`（6 个变体） | **`Windows (R) Win 7 DDK provider`** / `Blue Perfmon Driver` / `1.0.1.5` | 又一个内核驱动，签名者字符串是**旧 DDK 占位名** |
| `arphadump.dll` / `arphaCrashReport.exe` | `2.2.66` / `Alibaba Group` | 崩溃采集 |
| `courgette.dll` | — | 二进制差分更新（Chromium 项目组件） |

三点值得注意：

1. **`msvcp120.dll` / `msvcr120.dll` 的版本串是 `built by: REL AliSec`** —— 这是**阿里安全团队自己编译**的运行时，不是微软原版。同一机器的系统目录里也有同名 DLL，但两者不是一回事。
2. **`BluePerfmon4_*.sys` 的签名者字符串是 `Windows (R) Win 7 DDK provider`** —— 这是**旧 DDK 编译产物的典型占位字符串**，不是一家公司名。看到这个字符串不代表"来自微软"，只代表"用旧 DDK 构建"。
3. `courgette.dll` 出现在安装目录里，说明更新机制使用**二进制差分**（只下差异部分），这也解释了为什么它更新频繁但体积增量小。

> ⚠️ 上表右列是**从文件名与元数据推测的角色**，属于线索而非结论。文件名的说服力弱于第 02 节的 API 证据，两者应分开看待。

---

## 5. 本节用到的鉴定方法（可复用）

| 手段 | 命令 | 可看出什么 |
|---|---|---|
| 服务注册项 | `reg export/bat query "HKLM\SYSTEM\CurrentControlSet\Services\<名>"` | 服务名 / **显示名** / `ImagePath` / `Start` / 运行账户 |
| PE 版本信息 | `(Get-Item x.exe).VersionInfo \| fl CompanyName,FileDescription,FileVersion,**OriginalFilename**` | 公司 / 描述 / 版本 / **原始文件名**（最容易暴露真相的一栏） |
| 二进制内嵌函数名 | 直接搜 ASCII 串（静态分析常用做法） | 它调用/注册了哪些系统机制（见 02） |
| 服务安装历史 | 系统日志 `7045` | 何时被安装、被安装过几次（见 04） |

**核心原则：不要按名字判断一个组件是什么。** 名字是产品命名的产物，`OriginalFilename`、内嵌函数名、注册的回调类型才是技术身份。

---

下一篇：[02 · 行为分析](02-behavior-analysis.md) —— 这些组件到底注册了哪些系统机制。
