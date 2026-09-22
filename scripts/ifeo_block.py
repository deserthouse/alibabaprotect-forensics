#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ifeo_block.py —— 阻止指定映像名启动（映像执行选项 / IFEO），可一键还原

原理
    Windows 创建进程时会按【映像文件名】查询：
        HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<名字>
    把该处的 Debugger 指向一个【不存在的路径】，则 CreateProcess 会因"找不到调试器"
    而直接失败 —— 目标程序永远不会被执行。

    特点：按名字全局生效（多份副本一条规则全覆盖）、不触碰目标文件、删键即还原。

本脚本支持的目标（实测确认的 4 个执行体）
    AlibabaProtect.exe / AliProtectUpdate.exe / AlibabaProtectCon.exe / pc-sdk-setup.exe

行为约束
    · 只写 Image File Execution Options 下的注册表键，不触碰任何程序文件。
    · 建立前会先备份原有条目，还原时只删自己建立的项。
    · 不修改服务、不禁用计划任务（那些见卸载指南）。

用法（需要管理员权限）
    python ifeo_block.py --status          # 查看当前状态（只读）
    python ifeo_block.py --apply           # 建立拦截
    python ifeo_block.py --remove          # 一键还原
    python ifeo_block.py --probe           # 一次性探针实验：验证机制真的生效

    --apply 附加参数
        --force      当某条目已存在且 Debugger 非本工具的桩时，强制覆盖（默认跳过）

    退出码：0 成功 / 1 失败
"""

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile

IFEO_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
TARGETS = ["AlibabaProtect.exe", "AliProtectUpdate.exe",
           "AlibabaProtectCon.exe", "pc-sdk-setup.exe"]
STUB = r"C:\Windows\System32\BLOCKED-By-Admin-No-Exec.exe"
BACKUP_NAME = "ifeo_block_backup.json"


# --------------------------------------------------------------------------- 基础

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                                          # noqa: BLE001
        return False


def require_admin():
    if not is_admin():
        print("✗ 需要管理员权限。")
        print("  请以管理员身份重新打开终端后重试。")
        sys.exit(1)


def key_path(name):
    return r"%s\%s" % (IFEO_ROOT, name)


def get_debugger(name):
    """返回该映像名当前的 Debugger 值；键或值不存在 → None"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path(name)) as k:
            try:
                return winreg.QueryValueEx(k, "Debugger")[0]
            except OSError:
                return None
    except OSError:
        return None


def key_exists(name):
    import winreg
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path(name)).Close()
        return True
    except OSError:
        return False


def set_debugger(name, value):
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path(name), 0,
                            winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, value)


def delete_key(name):
    import winreg
    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path(name))


def is_our_stub(value):
    return bool(value) and value.strip().lower() == STUB.lower()


# --------------------------------------------------------------------------- 备份

def backup_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), BACKUP_NAME)


def save_backup(entries):
    """把"建立拦截之前"的状态存下来，供还原时判断该删还是该恢复。"""
    path = backup_path()
    old = {}
    if os.path.isfile(path):
        try:
            old = json.load(open(path, encoding="utf-8"))
        except Exception:                                      # noqa: BLE001
            old = {}
    old.update(entries)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(old, f, ensure_ascii=False, indent=2)
    return path


def load_backup():
    path = backup_path()
    if not os.path.isfile(path):
        return {}
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:                                          # noqa: BLE001
        return {}


# --------------------------------------------------------------------------- 命令

def cmd_status():
    print("=" * 78)
    print("IFEO 拦截状态")
    print("=" * 78)
    print("  桩路径（故意不存在）: %s" % STUB)
    print("  该路径当前是否存在  : %s" % os.path.exists(STUB))
    print("")
    blocked = 0
    for name in TARGETS:
        exists = key_exists(name)
        dbg = get_debugger(name)
        if not exists:
            state = "无条目"
        elif dbg is None:
            state = "键存在但无 Debugger 值"
        elif is_our_stub(dbg):
            state = "已拦截（本工具桩）"
            blocked += 1
        else:
            state = "Debugger = %s（非本工具，未改动）" % dbg
        print("  %-24s %s" % (name, state))
    print("")
    print("  已拦截 %d / %d" % (blocked, len(TARGETS)))
    print("=" * 78)
    return 0


def cmd_apply(force=False):
    require_admin()
    print("=" * 78)
    print("建立 IFEO 拦截")
    print("=" * 78)
    print("  桩路径: %s  （存在? %s —— 应为 False）" % (STUB, os.path.exists(STUB)))
    print("")
    before = {}
    changed, skipped, failed = [], [], []
    for name in TARGETS:
        cur = get_debugger(name)
        before[name] = {"existed": key_exists(name), "debugger": cur}
        if cur is not None and not is_our_stub(cur) and not force:
            skipped.append((name, cur))
            print("  [跳过] %-24s 已存在其它 Debugger: %s（用 --force 覆盖）" % (name, cur))
            continue
        if is_our_stub(cur):
            print("  [已是] %-24s 已由本工具拦截" % name)
            continue
        try:
            set_debugger(name, STUB)
        except PermissionError as e:
            print("  [失败] %-24s 拒绝访问（%s）" % (name, e))
            print("         ↳ 即使终端是管理员也会出现：通常是【安全软件 HIPS 的注册表防护】")
            print("           在拦截 IFEO 子键的【新建】。请临时退出该安全软件后重试，")
            print("           或在其设置中为 IFEO 写入放行。详见文档 06 第 4.4 节。")
            failed.append((name, "PermissionError"))
            continue
        now = get_debugger(name)
        ok = is_our_stub(now)
        changed.append(name)
        print("  [%s] %-24s Debugger → %s" % ("成功" if ok else "失败", name, now))

    if changed:
        p = save_backup(before)
        print("\n  已备份原状态 → %s" % p)
    print("")
    print("  新建/更新 %d 项，跳过 %d 项，失败 %d 项"
          % (len(changed), len(skipped), len(failed)))
    print("")
    if failed:
        print("  ⚠️ 有 %d 项写入失败 —— 拦截不完整，请先处理后再验证。" % len(failed))
    else:
        print("  ⚠️ 只写注册表还不够，请用 --probe 做功能验证（见文档 05）。")
    print("=" * 78)
    return 1 if failed else 0


def cmd_remove(assume_yes=False):
    require_admin()
    if not assume_yes:
        print("即将【删除或恢复】IFEO 拦截条目 —— 这会使防复发保护失效。")
        try:
            ans = input("确认继续？输入 yes 后回车: ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "yes":
            print("已取消（未做任何改动）。")
            return 1
    print("=" * 78)
    print("还原 IFEO 拦截")
    print("=" * 78)
    bak = load_backup()
    removed, restored, kept = [], [], []
    for name in TARGETS:
        cur = get_debugger(name)
        if cur is None and not key_exists(name):
            print("  [无]   %-24s 无条目" % name)
            continue
        if not is_our_stub(cur):
            kept.append(name)
            print("  [保留] %-24s Debugger 非本工具桩，未改动" % name)
            continue
        orig = bak.get(name) or {}
        if orig.get("existed") and orig.get("debugger"):
            set_debugger(name, orig["debugger"])
            restored.append(name)
            print("  [恢复] %-24s Debugger → %s" % (name, orig["debugger"]))
        else:
            delete_key(name)
            removed.append(name)
            print("  [删除] %-24s 键已删除" % name)
    print("")
    print("  删除 %d 项，恢复 %d 项，保留 %d 项" % (len(removed), len(restored), len(kept)))
    print("=" * 78)
    return 0


def cmd_probe():
    """一次性探针实验：用一个全新的映像名证明拦截机制真的生效。"""
    require_admin()
    probe_name = "IFEO_PROBE_TEST.exe"
    tmpdir = tempfile.mkdtemp(prefix="ifeo_probe_")
    probe = os.path.join(tmpdir, probe_name)
    hostname = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "hostname.exe")

    print("=" * 78)
    print("一次性探针实验：验证 IFEO 拦截真的生效")
    print("=" * 78)
    print("  设计：用一次性映像名 %s + 无害可执行体 hostname.exe" % probe_name)
    print("        先证明能跑 → 再加拦截证明跑不了 → 最后清理")
    print("")

    if not os.path.isfile(hostname):
        print("✗ 找不到 %s，无法进行实验" % hostname)
        return 1
    shutil.copy2(hostname, probe)
    print("--- 1) 造探针 ---")
    print("  探针文件 = %s   存在=%s   大小=%d"
          % (probe, os.path.isfile(probe), os.path.getsize(probe)))

    def run_probe():
        try:
            p = subprocess.run([probe], capture_output=True, timeout=15)
            out = (p.stdout or b"").decode("utf-8", "replace").strip()
            return True, "输出=%r  exit=%d" % (out, p.returncode)
        except Exception as e:                                 # noqa: BLE001
            return False, "CreateProcess 失败: %s" % e

    print("\n--- 2) 拦截前先跑一次（应当成功）---")
    ok1, msg1 = run_probe()
    print("  %s" % msg1)
    print("  → %s" % ("✅ 可正常执行（符合预期）" if ok1 else "⚠️ 居然跑不起来，实验前提不成立"))
    if not ok1:
        print("  中止实验（前提不成立）。")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return 1

    print("\n--- 3) 加 IFEO 拦截（Debugger → 不存在的路径）---")
    prev = get_debugger(probe_name)
    try:
        set_debugger(probe_name, STUB)
    except PermissionError as e:
        print("  ✗ 写入被拒绝: %s" % e)
        print("    通常原因：安全软件（HIPS）的注册表防护拦截了 IFEO 子键的【新建】。")
        print("    请临时退出该安全软件后重试（详见文档 06 第 4.4 节）。")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return 1
    print("  已写入: HKLM\\%s\\%s" % (IFEO_ROOT, probe_name))
    print("          Debugger = %s" % get_debugger(probe_name))

    print("\n--- 4) 拦截后再跑一次（应当失败）---")
    ok2, msg2 = run_probe()
    print("  %s" % msg2)
    print("  → %s" % ("✅ 拦截生效（CreateProcess 被拒绝）" if not ok2
                    else "❌ 拦截未生效 —— 机制需要重新检查"))

    print("\n--- 5) 清理探针 ---")
    if prev is None:
        try:
            delete_key(probe_name)
            print("  IFEO 键已删 = True")
        except OSError as e:
            print("  IFEO 键删除失败: %s" % e)
    else:
        set_debugger(probe_name, prev)
        print("  IFEO 键已恢复为原值: %s" % prev)
    shutil.rmtree(tmpdir, ignore_errors=True)
    print("  探针文件已删 = %s" % (not os.path.exists(probe)))

    print("\n--- 6) 确认正式拦截未受影响 ---")
    n = 0
    for name in TARGETS:
        b = is_our_stub(get_debugger(name))
        n += 1 if b else 0
        print("  %-24s %s" % (name, "✅ BLOCKED" if b else "— 未拦截"))
    print("  已拦截 %d / %d" % (n, len(TARGETS)))

    print("")
    print("结论: %s" % ("拦截机制已验证有效（拦截前可运行 → 拦截后 CreateProcess 失败）"
                      if (ok1 and not ok2) else "未取得完整证据，见上方各项"))
    print("=" * 78)
    return 0 if (ok1 and not ok2) else 1


def main():
    ap = argparse.ArgumentParser(
        description="IFEO 映像拦截：建立 / 查看 / 一键还原（阻止 AlibabaProtect 系列映像启动）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--apply", action="store_true", help="建立拦截（写注册表）")
    g.add_argument("--remove", action="store_true", help="一键还原（删/恢复注册表键）")
    g.add_argument("--status", action="store_true", help="查看当前状态（只读）")
    g.add_argument("--probe", action="store_true", help="一次性探针实验，验证机制生效")
    ap.add_argument("--force", action="store_true",
                    help="--apply 时强制覆盖已存在的其它 Debugger 值")
    ap.add_argument("--yes", action="store_true",
                    help="--remove 时跳过交互确认（脚本化场景使用）")
    args = ap.parse_args()

    if args.status:
        return cmd_status()
    if args.apply:
        return cmd_apply(force=args.force)
    if args.remove:
        return cmd_remove(assume_yes=args.yes)
    if args.probe:
        return cmd_probe()
    return 1


if __name__ == "__main__":
    sys.exit(main())
