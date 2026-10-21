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
    · 建立前会先备份原有键的全部值，还原时完整写回；桩路径意外存在时拒绝执行。
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

# 中文控制台默认 GBK，输出 ⚠️ 等 emoji 会 UnicodeEncodeError（实际发生在 --apply 成功后的提示行）
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")

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


def delete_value(name, value_name):
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path(name), 0,
                        winreg.KEY_SET_VALUE) as k:
        winreg.DeleteValue(k, value_name)


def is_our_stub(value):
    return bool(value) and value.strip().lower() == STUB.lower()


def check_stub_absent():
    """拦截机制的前提：桩路径必须不存在。若存在，'拦截'会退化成'重定向执行该文件'。"""
    if os.path.exists(STUB):
        print("✗ 桩路径 %s 竟然存在 —— 此时 Debugger 将重定向到该文件执行，而非拦截。" % STUB)
        print("  请先确认该文件来历并删除它，再重试。")
        return False
    return True


def read_key_values(name):
    """读取键下全部值（IFEO 键为扁平结构，无子键），供还原时完整写回。

    REG_BINARY 值以 "__b64__" 前缀 + base64 存入备份（JSON 不支持 bytes）。"""
    import base64
    import winreg
    out = None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path(name)) as k:
            out = {}
            i = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(k, i)
                    if isinstance(vdata, bytes):
                        vdata = "__b64__" + base64.b64encode(vdata).decode("ascii")
                    out[vname] = [vdata, vtype]
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return out


def write_key_values(name, values):
    """把备份的键值完整写回（重建键）。"""
    import base64
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path(name), 0,
                            winreg.KEY_SET_VALUE) as k:
        for vname, (vdata, vtype) in values.items():
            if isinstance(vdata, str) and vdata.startswith("__b64__"):
                vdata = base64.b64decode(vdata[len("__b64__"):])
            winreg.SetValueEx(k, vname, 0, vtype, vdata)


def restore_key(name, values):
    """恢复原键值，并撤除本工具加入的改动（AF-01）：

    1. 写回备份中的全部值；
    2. 若备份值里没有 Debugger、而当前 Debugger 是本工具桩 —— 删除该值
       （此前的实现只写回原值、不删后加的 Debugger，导致"还原成功但仍被拦截"）。
    其余当前存在但备份里没有的值（可能来自第三方）不动。"""
    write_key_values(name, values)
    if "Debugger" not in values and is_our_stub(get_debugger(name)):
        delete_value(name, "Debugger")


# --------------------------------------------------------------------------- 备份

def backup_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), BACKUP_NAME)


def save_backup(entries):
    """持久化备份并回读校验（AF-02）：原子写入（临时文件 + os.replace），

    写后重新解析并与待存内容比对，校验不过视为失败。
    只在【首次修改前】调用；已记录的条目不会被重写。"""
    path = backup_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
        back = json.load(open(tmp, encoding="utf-8"))
        if back != entries:
            raise ValueError("回读内容与待存内容不一致")
        os.replace(tmp, path)
    except Exception as e:                                        # noqa: BLE001
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print("✗ 备份无法持久化或校验失败（%s）。" % e)
        return None
    return path


def load_backup():
    """读取备份。返回 (entries, problem)：problem 为 None / "missing" / "corrupt"。

    调用方必须区分三种状态：损坏/缺失时不得猜测"原态不存在"（AF-02 失败关闭）。"""
    path = backup_path()
    if not os.path.isfile(path):
        return {}, "missing"
    try:
        data = json.load(open(path, encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("备份顶层不是对象")
        return data, None
    except Exception as e:                                        # noqa: BLE001
        print("✗ 备份文件损坏（%s）: %s" % (path, e))
        return {}, "corrupt"


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
    if not check_stub_absent():
        return 1
    bak, problem = load_backup()
    if problem == "corrupt":
        print("✗ 备份文件损坏 —— 拒绝继续（继续可能丢失既有条目的原态）。")
        print("  请人工检查 %s 后再试。" % backup_path())
        return 1
    plan = []           # 本次将写入的 (名字, 原态快照)
    changed, skipped, failed = [], [], []
    for name in TARGETS:
        cur = get_debugger(name)
        if cur is not None and not is_our_stub(cur) and not force:
            skipped.append((name, cur))
            print("  [跳过] %-24s 已存在其它 Debugger: %s（用 --force 覆盖）" % (name, cur))
            continue
        if is_our_stub(cur):
            print("  [已是] %-24s 已由本工具拦截" % name)
            continue
        plan.append((name, {"existed": key_exists(name), "debugger": cur,
                            "values": read_key_values(name)}))
    if plan:
        # AF-02：备份在【任何注册表写入之前】持久化并校验；
        # 已在备份中的条目不重写（避免部分失败后重试把"原态"覆盖成"已拦截态"）。
        merged = dict(bak)
        for name, snap in plan:
            merged.setdefault(name, snap)
        p = save_backup(merged)
        if p is None:
            print("✗ 未做任何注册表修改（备份先行失败）。")
            return 1
        print("  已备份原状态 → %s（先备份后写入）" % p)
    print("")
    for name, _snap in plan:
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
    print("")
    print("  新建/更新 %d 项，跳过 %d 项，失败 %d 项"
          % (len(changed), len(skipped), len(failed)))
    print("")
    if failed:
        print("  ⚠️ 有 %d 项写入失败 —— 拦截不完整。原态备份已保存，重试直接再跑本命令" % len(failed))
        print("     即可（不会覆盖已记录的原态）。")
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
    bak, problem = load_backup()
    removed, restored, kept, held = [], [], [], []
    for name in TARGETS:
        cur = get_debugger(name)
        if cur is None and not key_exists(name):
            print("  [无]   %-24s 无条目" % name)
            continue
        if not is_our_stub(cur):
            kept.append(name)
            print("  [保留] %-24s Debugger 非本工具桩，未改动" % name)
            continue
        orig = bak.get(name)
        # AF-02 失败关闭：备份缺失/损坏时不猜测"原态不存在"，不删不改，转人工。
        if orig is None and problem in ("missing", "corrupt"):
            held.append(name)
            print("  [止手] %-24s 桩存在但备份%s —— 不自动删除/恢复。" %
                  (name, "文件缺失" if problem == "missing" else "文件损坏"))
            print("         人工路径：注册表 HKLM\\%s\\%s 删除 Debugger 值，"
                  "或确认无需保留后删键。" % (IFEO_ROOT, name))
            continue
        if orig is not None and orig.get("existed") and orig.get("values") is not None:
            restore_key(name, orig["values"])
            restored.append(name)
            print("  [恢复] %-24s 原键值已写回并撤除本工具 Debugger（%d 个值）"
                  % (name, len(orig["values"])))
        elif orig is not None and orig.get("existed") and orig.get("debugger"):
            # 旧版备份只有 debugger 字段（无全值快照），尽力恢复已知值
            set_debugger(name, orig["debugger"])
            restored.append(name)
            print("  [恢复] %-24s Debugger → %s（旧版备份，仅恢复 Debugger 值）"
                  % (name, orig["debugger"]))
        else:
            delete_key(name)
            removed.append(name)
            print("  [删除] %-24s 键已删除（备份记录：原键不存在）" % name)
    print("")
    print("  删除 %d 项，恢复 %d 项，保留 %d 项，止手 %d 项"
          % (len(removed), len(restored), len(kept), len(held)))
    if held:
        print("  ⚠️ 有条目因备份缺失/损坏未处理 —— 拦截仍在生效，请按上面的人工路径处理。")
        return 1
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
    if not check_stub_absent():
        return 1

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
