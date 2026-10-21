# 真实环境回归计划 — ifeo_block（未执行）

2026-10-21 取证复核 AF-01/AF-02 关闭条件的"实际回读验证"部分。脚本修复（49b9d26）已通过 29 项隔离测试（tests/test_ifeo_and_verify.py，内存假注册表）；以下为**真实 Windows 注册表**的完整回归，需在可随意折腾的测试机执行——**不要在装有本工具正式拦截的机器上跑**（remove 会撤除防复发）。

## 前置

- 干净测试机（或快照可回滚的 VM），管理员 PowerShell/Python 3.x
- 确认无安全软件拦截 IFEO（或按 docs/06 §4.4 临时退出）

## 用例（每例先 `--status` 留底，后 `--status` 复核）

| # | 前态构造 | 操作 | 通过标准 |
|---|---|---|---|
| 1 | 目标键不存在 | apply → remove | 键被删除；status 无残留 |
| 2 | 键存在、仅 GlobalFlag 无 Debugger | apply → remove | GlobalFlag 保留、Debugger 值消失（AF-01 本体） |
| 3 | 键存在、外来自定义 Debugger | apply（无 --force 应跳过）；apply --force → remove | 原 Debugger 精确恢复 |
| 4 | 部分失败重试 | 人为让首目标写入失败（如临时 ACL），apply → 解除 → apply → remove | 全部恢复为真原态（AF-02 本体：备份未被重试覆盖） |
| 5 | 备份损坏/缺失 | apply 后删/改坏 backup.json → remove | 拒绝自动删除、退出码 1、给出人工路径 |
| 6 | 探针 | --probe | 拦截前可运行/拦截后拒绝/清理后键与临时目录消失 |
| 7 | 真实目标验证 | apply 后实际尝试启动四个目标映像名之一的副本 | CreateProcess 失败；remove 后可启动 |

## 产出

结果表回填本文件；任何与隔离测试不一致的行为按缺陷记录并回归 tests/。通过后：README"还原边界"一句与指南下载点可去掉"真实环境未回归"限定（当前两处均如实标注）。
