#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_clean.py —— 清理【后】的核验清单（只读）

用途
    证明"它确实没回来"，而不是"看起来好像没了"。
    对应卸载指南第五节的五项清单，并补充驱动、残留目录与防复发状态。

行为约束
    只读。不修改服务、注册表、文件，不结束进程，不联网。

用法
    python verify_clean.py

退出码
    0 = 判定项（第 1~5 项）全部通过 —— 清理完成
    1 = 判定项有未通过 —— 清理未完成
    （补充项/信息项未通过不影响退出码，仅在输出中提示）

说明
    · 第 1~5 项为"清理完成"的判定项。
    · 第 6~8 项为补充项（驱动与残留数据），建议一并处理。
    · 第 9 项为【信息项】：若你做过防复发（IFEO），条目存在是【预期】状态，不算失败。
"""

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys

# --------------------------------------------------------------------------- 目标

SERVICE_NAMES = ["AlibabaProtect", "AliPaladin"]
PROCESS_NAMES = ["alibabaprotect.exe", "alipaladin.exe",
                 "aliprotectupdate.exe", "alibabaprotectcon.exe", "pc-sdk-setup.exe"]
INSTALL_DIRS = [r"C:\Program Files (x86)\AlibabaProtect"]
LEFTOVER_DIRS = [r"C:\ProgramData\Alibaba\AlibabaProtectDT"]
DRIVER_FILES_KNOWN = [r"C:\Windows\System32\drivers\AliPaladinEx64.sys"]


def driver_paths():
    """应检查的驱动文件：以服务键 ImagePath 现取为准（不同机器/版本可能指向
    AliPaladin64.sys 等变体），另加 drivers 目录通配与已知默认路径兜底。"""
    import glob
    paths = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\AliPaladin") as k:
            try:
                ip = winreg.QueryValueEx(k, "ImagePath")[0].strip()
                if ip.startswith("\\??\\"):
                    ip = ip[4:]
                paths.append(ip)
            except OSError:
                pass
    except OSError:
        pass
    paths.extend(glob.glob(r"C:\Windows\System32\drivers\AliPaladin*.sys"))
    paths.extend(DRIVER_FILES_KNOWN)
    seen, out = set(), []
    for p in paths:
        if p and p.lower() not in seen:
            seen.add(p.lower())
            out.append(p)
    return out
REG_SERVICE_KEYS = [r"SYSTEM\CurrentControlSet\Services\%s" % n for n in SERVICE_NAMES]
IFEO_NAMES = ["AlibabaProtect.exe", "AliProtectUpdate.exe",
              "AlibabaProtectCon.exe", "pc-sdk-setup.exe"]
IFEO_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


# ----------------------------------------------------------------------- 检测原语

def run_text(args, timeout=40, with_rc=False):
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    raw = p.stdout or b""
    for enc in ("utf-8", "gbk", "mbcs", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        text = raw.decode("utf-8", "replace")
    if with_rc:
        return text, p.returncode
    return text


def service_query(name):
    """返回 (exists: bool, raw_text)"""
    try:
        text, rc = run_text(["sc.exe", "query", name], timeout=15, with_rc=True)
    except Exception as e:                                     # noqa: BLE001
        return None, "查询异常: %s" % e
    # sc.exe 失败时以 Win32 错误码作为退出码。
    # 1060 = ERROR_SERVICE_DOES_NOT_EXIST（服务从未注册/已注销）
    # 2   = ERROR_FILE_NOT_FOUND（注册表键已删、SCM 数据库未刷新的过渡态）
    if rc in (1060, 2):
        return False, text
    return True, text


def reg_key_exists(path):
    try:
        import winreg
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path).Close()
            return True
        except OSError:
            return False
    except ImportError:
        return None


def reg_read(path, value):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return None


def enum_processes(names):
    found = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return found
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() in names:
                found.append((pe.th32ProcessID, pe.szExeFile))
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    return found


def find_tasks(prefix="Ali"):
    hits, err = [], None
    try:
        text = run_text(["schtasks", "/query", "/fo", "CSV", "/nh"])
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith('"'):
                continue
            name = line.split('","')[0].strip('"').lstrip("\\")
            if name.lower().startswith(prefix.lower()):
                parts = [x.strip('"') for x in line.split('","')]
                hits.append((name, parts[2] if len(parts) > 2 else ""))
    except Exception as e:                                     # noqa: BLE001
        err = str(e)
    return hits, err


# --------------------------------------------------------------------------- 主流程

def main():
    results = []          # (基本项?, 名称, 通过?, 详情)

    # --- 1. 服务不存在 ---
    for name in SERVICE_NAMES:
        exists, text = service_query(name)
        if exists is None:
            results.append((True, "服务 %s 不存在" % name, False, text))
        elif exists:
            results.append((True, "服务 %s 不存在" % name, False,
                            "仍然存在（sc query 退出码非 1060/2）"))
        else:
            results.append((True, "服务 %s 不存在" % name, True, "已确认：1060 服务未安装"))

    # --- 2. 进程不在运行 ---
    procs = enum_processes({n.lower() for n in PROCESS_NAMES})
    if procs:
        results.append((True, "相关进程未运行", False,
                        "仍在运行: " + ", ".join("%s(PID=%d)" % (n, p) for p, n in procs)))
    else:
        results.append((True, "相关进程未运行", True, "未发现同名进程"))

    # --- 3. 安装目录不存在 ---
    for d in INSTALL_DIRS:
        if os.path.exists(d):
            results.append((True, "安装目录不存在", False, "仍存在: %s" % d))
        else:
            results.append((True, "安装目录不存在", True, d))

    # --- 4. 服务注册表键不存在 ---
    for key in REG_SERVICE_KEYS:
        if reg_key_exists(key):
            results.append((True, "注册表键 %s 不存在" % key.split("\\")[-1], False,
                            r"HKLM\%s 仍存在" % key))
        else:
            results.append((True, "注册表键 %s 不存在" % key.split("\\")[-1], True, "已确认找不到项"))

    # --- 5. 无相关计划任务（或已禁用）---
    tasks, err = find_tasks("Ali")
    if err:
        results.append((True, "无启用的 Ali 相关计划任务", False, "查询失败: %s" % err))
    else:
        enabled = [t for t, st in tasks
                   if st and st not in ("已禁用", "Disabled", "N/A", "")]
        if enabled:
            results.append((True, "无启用的 Ali 相关计划任务", False,
                            "仍启用: " + ", ".join(enabled)))
        elif tasks:
            results.append((True, "无启用的 Ali 相关计划任务", True,
                            "存在但已禁用: " + ", ".join("%s(%s)" % t for t in tasks)))
        else:
            results.append((True, "无启用的 Ali 相关计划任务", True, "未发现相关任务"))

    # --- 6. 驱动文件不存在（补充项）---
    for f in driver_paths():
        if os.path.exists(f):
            results.append((False, "驱动文件不存在", False, "仍存在: %s" % f))
        else:
            results.append((False, "驱动文件不存在", True, f))

    # --- 7. 残留数据目录（补充项，通常无害但建议清理）---
    for d in LEFTOVER_DIRS:
        if os.path.exists(d):
            n = 0
            for _root, _dirs, files in os.walk(d):
                n += len(files)
            results.append((False, "残留数据目录已清理", False,
                            "仍存在: %s（%d 个文件，通常无害）" % (d, n)))
        else:
            results.append((False, "残留数据目录已清理", True, d))

    # --- 8. IFEO 信息项 ---
    blocked = []
    for name in IFEO_NAMES:
        path = r"%s\%s" % (IFEO_ROOT, name)
        if reg_read(path, "Debugger"):
            blocked.append(name)
    results.append((False, "防复发状态（信息项）", True,
                    "已拦截 %d/%d 个映像：%s" % (len(blocked), len(IFEO_NAMES),
                                             ", ".join(blocked)) if blocked
                    else "未设置 IFEO 拦截 —— 客户端更新时可能被重新安装"))

    # ------------------------------------------------------------------ 输出
    core = [r for r in results if r[0]]
    extra = [r for r in results if not r[0]]

    print("=" * 78)
    print("AlibabaProtect 清理核验清单")
    print("=" * 78)
    print("")
    print("【判定项】清理是否完成")
    for _core, label, ok, detail in core:
        print("  [%s] %-34s %s" % ("通过" if ok else "未通过", label, detail))
    print("")
    print("【补充项】驱动与残留数据")
    for _core, label, ok, detail in extra:
        print("  [%s] %-34s %s" % ("通过" if ok else "未通过", label, detail))
    print("")

    failed = [r for r in results if not r[2]]
    core_failed = [r for r in core if not r[2]]

    print("=" * 78)
    if not failed:
        print("结果：全部通过 —— 清理完成，且未发现回流迹象。")
    elif not core_failed:
        print("结果：判定项全部通过（清理完成）。")
        print("      补充项有 %d 项未通过（不影响结论，建议顺手处理）：" % len(failed))
        for _c, label, _ok, detail in failed:
            print("        · %s —— %s" % (label, detail))
    else:
        print("结果：判定项有 %d 项未通过 —— 清理尚未完成：" % len(core_failed))
        for _c, label, _ok, detail in core_failed:
            print("        · %s —— %s" % (label, detail))
        print("      请对照卸载指南的『备选路径』（两阶段：先禁用 + 重启，再删除）。")
    print("")
    print("退出码: %d   （0 = 判定项全部通过；1 = 判定项有未通过 = 清理未完成。"
          "补充项未通过不影响退出码）" % (1 if core_failed else 0))
    print("=" * 78)

    return 1 if core_failed else 0


if __name__ == "__main__":
    sys.exit(main())
