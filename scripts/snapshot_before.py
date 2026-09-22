#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
snapshot_before.py —— 清理【前】的状态快照（只读）

用途
    在动任何东西之前，先把"它现在长什么样"完整记录下来。
    这样清理后才有可对比的基线，也便于日后回溯。

记录内容
    · 服务          AlibabaProtect / AliPaladin 是否存在、启动类型、镜像路径、显示名
    · 进程          是否有同名进程在跑，累计 CPU 时间 / 工作集 / 线程数 / 句柄数
    · 计划任务      名称以 Ali 开头的任务及其状态
    · 文件系统      已知的安装目录、版本子目录、驱动文件
    · IFEO          映像执行选项里是否已存在相关拦截条目

行为约束
    只读。不修改服务、注册表、文件，不结束进程，不联网。

用法
    python snapshot_before.py                 # 打印报告
    python snapshot_before.py before.json     # 同时写入 JSON（便于日后 diff）
"""

import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
from datetime import datetime

# --------------------------------------------------------------------------- 常量

SERVICE_NAMES = ["AlibabaProtect", "AliPaladin"]
PROCESS_NAMES = ["alibabaprotect.exe", "alipaladin.exe",
                 "aliprotectupdate.exe", "alibabaprotectcon.exe", "pc-sdk-setup.exe"]
IFEO_NAMES = ["AlibabaProtect.exe", "AliProtectUpdate.exe",
              "AlibabaProtectCon.exe", "pc-sdk-setup.exe"]
IFEO_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

INSTALL_DIRS = [
    r"C:\Program Files (x86)\AlibabaProtect",
    r"C:\ProgramData\Alibaba\AlibabaProtectDT",
]
DRIVER_FILES = [r"C:\Windows\System32\drivers\AliPaladinEx64.sys"]

STUB = r"C:\Windows\System32\BLOCKED-By-Admin-No-Exec.exe"

# 服务启动类型 / 状态码
START_TYPES = {0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled"}
WIN32_ERROR_NO_SERVICE = 1060

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# ------------------------------------------------------------------- 进程枚举（toolhelp32）

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


def ft_to_int(ft):
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def enum_matching_processes(names):
    """返回 [(pid, exe_name, parent_pid)]，只取名字命中 names 的进程。"""
    out = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap == ctypes.c_void_p(-1).value:
        return out
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            name = pe.szExeFile
            if name.lower() in names:
                out.append((pe.th32ProcessID, name, pe.th32ParentProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    return out


def process_details(pid):
    """累计 CPU 秒、工作集 MB、线程数。取不到就返回 None。"""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        creation, exit_, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not kernel32.GetProcessTimes(h, ctypes.byref(creation), ctypes.byref(exit_),
                                        ctypes.byref(kernel), ctypes.byref(user)):
            return None
        k = ft_to_int(kernel)
        u = ft_to_int(user)
        d = {}
        d["cpu_seconds"] = round((k + u) / 1e7, 1)
        # 启动时间：FILETIME(1601) → Unix
        c = ft_to_int(creation)
        if c > 0:
            d["start_time"] = datetime.fromtimestamp(c / 1e7 - 11644473600).strftime(
                "%Y-%m-%d %H:%M:%S")
        # 线程/句柄/内存
        cnt = wt.DWORD(0)
        if kernel32.GetProcessHandleCount(h, ctypes.byref(cnt)):
            d["handles"] = cnt.value
        return d
    finally:
        kernel32.CloseHandle(h)


# ----------------------------------------------------------------------- 服务查询

def query_service(name):
    """用 sc.exe query 取状态；用 winreg 取配置。服务不存在 → {"installed": False}"""
    info = {"installed": False}
    try:
        text = run_text(["sc.exe", "query", name], timeout=15)
        if "1060" in text or "does not exist" in text or "指定的服务" in text:
            return info
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("STATE"):
                parts = line.split()
                if len(parts) >= 4:
                    info["state"] = parts[3]
                    info["installed"] = True
    except Exception as e:                                     # noqa: BLE001
        info["error"] = str(e)
    # 配置（winreg 只读）
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\%s" % name) as k:
            info["installed"] = True
            for field, label in (("DisplayName", "display_name"), ("ImagePath", "image_path"),
                                 ("ObjectName", "object_name")):
                try:
                    info[label] = winreg.QueryValueEx(k, field)[0]
                except OSError:
                    pass
            try:
                st = winreg.QueryValueEx(k, "Start")[0]
                info["start_type"] = START_TYPES.get(st, str(st))
            except OSError:
                pass
    except OSError:
        pass
    return info


def query_ifeo():
    out = {}
    try:
        import winreg
        for name in IFEO_NAMES:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"%s\%s" % (IFEO_ROOT, name)) as k:
                    try:
                        dbg = winreg.QueryValueEx(k, "Debugger")[0]
                    except OSError:
                        dbg = None
                    out[name] = {"present": True, "debugger": dbg,
                                 "is_our_stub": bool(dbg) and dbg.lower() == STUB.lower()}
            except OSError:
                out[name] = {"present": False, "debugger": None, "is_our_stub": False}
    except ImportError:
        pass
    return out


def run_text(args, timeout=40):
    """执行命令并按控制台编码解码输出（中文 Windows 下 console 用 GBK）。"""
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    raw = p.stdout or b""
    for enc in ("utf-8", "gbk", "mbcs", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def query_tasks(prefix="Ali"):
    tasks = []
    try:
        text = run_text(["schtasks", "/query", "/fo", "CSV", "/nh"])
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith('"'):
                continue
            name = line.split('","')[0].strip('"').lstrip("\\")
            if name.lower().startswith(prefix.lower()):
                parts = [x.strip('"') for x in line.split('","')]
                tasks.append({"name": name,
                              "next_run": parts[1] if len(parts) > 1 else "",
                              "status": parts[2] if len(parts) > 2 else ""})
    except Exception as e:                                     # noqa: BLE001
        tasks.append({"error": str(e)})
    return tasks


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                                          # noqa: BLE001
        return False


# --------------------------------------------------------------------------- 主流程

def collect():
    snap = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_admin": is_admin(),
        "services": {},
        "processes": [],
        "scheduled_tasks": query_tasks(),
        "filesystem": {},
        "ifeo": query_ifeo(),
    }
    for s in SERVICE_NAMES:
        snap["services"][s] = query_service(s)

    names = {n.lower() for n in PROCESS_NAMES}
    for pid, name, ppid in enum_matching_processes(names):
        d = process_details(pid) or {}
        d.update({"pid": pid, "name": name, "parent_pid": ppid})
        snap["processes"].append(d)

    for p in INSTALL_DIRS + DRIVER_FILES:
        e = {"exists": os.path.exists(p)}
        if e["exists"]:
            try:
                e["size"] = os.path.getsize(p)
            except OSError:
                pass
        snap["filesystem"][p] = e

    # 安装目录下的版本子目录
    base = INSTALL_DIRS[0]
    if os.path.isdir(base):
        try:
            snap["version_dirs"] = sorted(
                d for d in os.listdir(base)
                if os.path.isdir(os.path.join(base, d)))
        except OSError:
            pass
    return snap


def render(snap):
    L = []
    A = L.append
    A("=" * 78)
    A("AlibabaProtect 清理【前】状态快照")
    A("生成时间: %s      管理员权限: %s" % (snap["generated_at"],
                                    "是" if snap["is_admin"] else "否（只读快照不需要）"))
    A("=" * 78)

    A("")
    A("--- 服务 ---")
    for name, info in snap["services"].items():
        if not info.get("installed"):
            A("  %-18s 未安装（或查询失败）" % name)
            continue
        A("  %-18s 已安装" % name)
        if info.get("display_name"):
            A("      显示名     : %s" % info["display_name"])
        if info.get("state"):
            A("      当前状态   : %s" % info["state"])
        if info.get("start_type"):
            A("      启动类型   : %s" % info["start_type"])
        if info.get("object_name"):
            A("      运行账户   : %s" % info["object_name"])
        if info.get("image_path"):
            A("      镜像路径   : %s" % info["image_path"])

    A("")
    A("--- 进程 ---")
    if not snap["processes"]:
        A("  无同名进程在运行")
    for p in snap["processes"]:
        A("  %s  PID=%d  父PID=%s" % (p.get("name"), p.get("pid"), p.get("parent_pid", "?")))
        if "cpu_seconds" in p:
            A("      累计 CPU   : %.1f 秒" % p["cpu_seconds"])
        if "start_time" in p:
            A("      启动时间   : %s" % p["start_time"])
        if "handles" in p:
            A("      句柄数     : %d" % p["handles"])

    A("")
    A("--- 计划任务（Ali 开头）---")
    if not snap["scheduled_tasks"]:
        A("  无")
    for t in snap["scheduled_tasks"]:
        if "error" in t:
            A("  查询出错: %s" % t["error"])
        else:
            A("  %-26s 状态=%-10s 下次运行=%s" % (t["name"], t["status"], t["next_run"]))

    A("")
    A("--- 文件系统 ---")
    for path, e in snap["filesystem"].items():
        if e.get("exists"):
            sz = e.get("size")
            A("  存在   %s%s" % (path, ("   (%d 字节)" % sz) if sz else ""))
        else:
            A("  不存在 %s" % path)
    if snap.get("version_dirs"):
        A("  版本子目录: %s" % ", ".join(snap["version_dirs"]))

    A("")
    A("--- 映像执行选项（IFEO）---")
    for name, e in snap["ifeo"].items():
        if not e.get("present"):
            A("  %-24s 无条目" % name)
        else:
            mark = "本工具的拦截桩" if e.get("is_our_stub") else "其它/未知 Debugger"
            A("  %-24s Debugger=%s   [%s]" % (name, e.get("debugger"), mark))

    A("")
    A("=" * 78)
    A("提示：清理并重启后，用 verify_clean.py 做同口径核验。")
    A("=" * 78)
    return "\n".join(L)


def main():
    out_json = sys.argv[1] if len(sys.argv) > 1 else None
    snap = collect()
    print(render(snap))
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)
        print("\n[已写入 JSON] %s" % os.path.abspath(out_json))


if __name__ == "__main__":
    main()
