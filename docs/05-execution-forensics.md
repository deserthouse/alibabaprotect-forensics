# 05 · 执行级取证：证明"它到底跑没跑"

清理后最常见的问题不是"删掉了吗"，而是这个：

> **它现在没在运行 —— 是因为"没有被尝试启动"，还是因为"被尝试了但被拦住了"？**

这两者的结论完全相反：前者说明防复发措施还没被检验过，后者才说明拦截真的生效。本文记录两种**不依赖调试器**的判定手段。

---

## 1. Prefetch：程序是否**成功执行**过

### 原理

Windows 的预读（Prefetch）机制会为**实际启动过的**可执行文件，在 `C:\Windows\Prefetch\` 下生成 `<映像名>-<哈希>.pf` 文件。

> **`C:\Windows\Prefetch\<name>.pf` 的存在 = "该映像曾经成功启动过"的强证据。**

### 核心技巧：把它和"最后访问时间"交叉

单看 Prefetch 只能证明"跑过"。真正的价值在于两个维度交叉：

| Prefetch | 文件 `LastAccessTime` | 判定 |
|---|---|---|
| 存在 | 近期 | 确实运行过 |
| **不存在** | **近期** | ⭐ **被尝试启动过，但在创建进程阶段失败** —— **拦截生效**的指纹 |
| 不存在 | 陈旧 | 从未被尝试 |

**为什么成立**：启动进程时，内核会**先打开映像文件**（更新访问时间），随后才进入 `CreateProcess` 阶段。若在映像执行选项（IFEO）层面被拦，**文件已被"碰过"，进程却从未创建** —— 于是留下"有访问、无记录"的组合。

### 实测案例

在一次防复发验证中，目标程序在外部触发的应当尝试启动。检查结果：

```powershell
Get-ChildItem C:\Windows\Prefetch -Filter "ALIBABAPROTECT*"   # → 无
Get-ChildItem C:\Windows\Prefetch -Filter "ALIPALADIN*"      # → 无

(Get-Item '...\AlibabaProtectCon.exe').LastAccessTime         # → 落在触发时刻，精确到秒
```

**两个关键执行体都无 Prefetch 记录，但其中一个的访问时间精确落在触发的秒数上** ⇒ 把"它没试过"这个可能性排除掉，结论是「**它试了，进不来**」。

**对照组**：同一次触发中，**上游更新器**（未被拦截）**有** Prefetch 记录 —— 这进一步确认"该触发确实发生过"，而不是我误判了触发时机。

### 实用命令

```powershell
# 某类程序是否运行过
Get-ChildItem C:\Windows\Prefetch -Filter "*.pf" |
    Where-Object { $_.Name -match 'ALIBABAPROTECT|ALIPALADIN|PC-SDK' } |
    Select-Object Name, LastWriteTime

# 最近 N 小时内运行过的所有程序（重建执行时间线）
Get-ChildItem C:\Windows\Prefetch -Filter "*.pf" |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
    Sort-Object LastWriteTime -Descending |
    Select-Object LastWriteTime, Name
```

> `LastWriteTime` 即该程序的**最后运行时刻**，可重建精确到秒的执行时间线。

---

## 2. 一次性探针实验：直接证明"拦截生效"

`Prefetch` 是**间接**证据。要**直接**证明拦截机制真的能拦住进程创建，最干净的做法是做一次**用一次性名字的自证实验** —— 用一个全新的文件名，先证明它**能**跑，再加上拦截，再证明它**跑不了**，最后清理干净。

### 实验设计要点

| 要求 | 做法 |
|---|---|
| 零风险 | 用**一次性映像名**（`IFEO_PROBE_TEST.exe`），不影响任何真实程序 |
| 可执行探针 | 复制系统自带的 `hostname.exe`（有确定输出、无副作用） |
| 前后对照 | 加拦截**前**运行一次（应成功）、**后**运行一次（应失败） |
| 可还原 | 实验结束删除 IFEO 键 + 删除探针文件 |
| 不干扰既有配置 | 结束时核对**既有的 4 条正式拦截**仍在 |

### 实验完整记录

```
=== 探针实验：证明 IFEO 拦截机制真的生效（用一次性名字，零风险）===

--- 1) 造一个可执行的探针（复制系统 hostname.exe）---
  探针文件 = ...\tests\IFEO_PROBE_TEST.exe | 存在=True | 大小=40960

--- 2) 拦截前先跑一次（应当成功执行）---
  执行结果 = '<主机名>'  exit=0   → ✅ 可正常执行（符合预期）

--- 3) 加 IFEO 拦截（Debugger → 不存在的路径）---
  已写入: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
          Image File Execution Options\IFEO_PROBE_TEST.exe
          Debugger = C:\Windows\System32\BLOCKED-By-Admin-No-Exec.exe

--- 4) 拦截后再跑一次（应当失败）---
  执行结果 = CreateProcess 失败: 由于出现以下错误，无法运行此命令: 系统找不到指定的文件。。
  → 判定: ✅ 拦截生效（CreateProcess 被拒绝）

--- 5) 清理探针（删 IFEO 键 + 删探针文件）---
  IFEO 键已删 = True
  探针文件已删 = True

--- 6) 确认 4 个正式拦截仍在 ---
  AlibabaProtect.exe        ✅ BLOCKED
  AliProtectUpdate.exe      ✅ BLOCKED
  AlibabaProtectCon.exe     ✅ BLOCKED
  pc-sdk-setup.exe          ✅ BLOCKED
  IFEO 子键总数 = 68  (应为 68)
```

### 这个实验证明了什么

| 结论 | 强度 |
|---|---|
| `Debugger` 指向不存在路径 ⇒ **`CreateProcess` 直接失败** | **直接证明**（同一程序，加拦截前成功、加拦截后失败） |
| 拦截**按映像名**生效，与文件路径无关 | **直接证明**（探针在临时目录，仍被拦） |
| 既有 4 条正式拦截未受影响 | **直接验证**（子键计数前后一致） |
| 清理后可完全还原 | **已验证**（键与文件均删除成功） |

原始记录见 `evidence/ifeo-probe-log.txt`。

> 这个实验的价值在于：**它不是"我认为它会生效"，而是"我让它试了一次，看着它失败"**。任何机制类结论都应该做到这一步。

---

## 3. 局限（必须知道）

| 局限 | 说明 |
|---|---|
| Prefetch 可能被禁用 | SSD 上系统默认可能关闭预读。**先确认 `C:\Windows\Prefetch` 有内容**，否则整套方法失效 |
| Prefetch 可能被清理 | 清理软件会删 `.pf` 文件 |
| **`LastAccessTime` 更新可能默认关闭** | Windows 10 1803+ 上 NTFS 的最后访问时间更新默认为 "System Managed"：**系统盘 > 128 GB 时默认关闭**（`fsutil behavior query disablelastaccess` 可查）。此时"访问时间落在触发时刻"这枚指纹**不会出现**，只剩 Prefetch 缺失一条腿（只能证明"没成功跑过"，无法区分"没试"与"被拦"）。本机实测时该指纹生效，说明本机该功能处于开启状态 |
| 只对"有预读价值"的程序生成 | 短命/极小的程序可能不生成记录 |
| 不含命令行参数 | 无法知道"是怎么被启动的" |
| 可被伪造/清除 | 对抗场景下不可依赖 |
| 探针实验需管理员权限 | 写 `HKLM` 下的 IFEO 键需要提权 |

**结论：Prefetch 适合"快速、无成本地验证执行与否"；探针实验适合"一次性确认拦截机制有效"。两者都不适合作为对抗环境下的唯一证据。**

---

## 4. 什么时候该用哪一种

| 场景 | 用哪个 |
|---|---|
| 日常检查"它最近有没有自行启动过" | **Prefetch**（几秒钟，只读） |
| 首次配置防复发后，要确认拦截真的有效 | **一次性探针实验**（一次即可） |
| 怀疑某个客户端更新触发了重装 | **Prefetch + SCM `7045` 事件**（交叉时间线，见 04） |
| 需要"它试过但被拦住"的证据 | **Prefetch 缺失 + `LastAccessTime` 近期** 组合 |

---

上一篇：[04 · 为什么删不干净](04-why-hard-to-remove.md) ｜ 下一篇：[06 · 防复发](06-prevent-recurrence.md)
