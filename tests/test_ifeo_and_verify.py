#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AF-01/02/03 修复的隔离测试（取证复核 2026-10-21 关闭条件）。

不触碰真实注册表：以内存假 winreg 替换 sys.modules['winreg']，
以假 schtasks 输出/假快照句柄验证 verify_clean 原语的三态语义。
运行：python tests/test_ifeo_and_verify.py（全过输出 ALL PASS）
"""
import importlib.util
import json
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
IFEO_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
STUB = r"C:\Windows\System32\BLOCKED-By-Admin-No-Exec.exe"

FAILURES = []


def check(label, cond):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", label))
    if not cond:
        FAILURES.append(label)


# ---------------------------------------------------------------- 假 winreg
class FakeWinreg(types.ModuleType):
    HKEY_LOCAL_MACHINE = 0
    REG_SZ = 1
    REG_DWORD = 4
    REG_BINARY = 3
    KEY_SET_VALUE = 0x0002
    KEY_QUERY_VALUE = 0x0001

    def __init__(self):
        super().__init__("winreg")
        self.hive = {}          # path(str) -> {valuename: [data, type]}
        self.deny_paths = set()  # 这些路径的一切访问抛 PermissionError

    class _Key:
        def __init__(self, mod, path):
            self._mod, self.path = mod, path

        def close(self):
            pass

        Close = close

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _denied(self, path):
        for d in self.deny_paths:
            if path.lower().startswith(d.lower()):
                return True
        return False

    def OpenKey(self, root, path, *a):
        if self._denied(path):
            raise PermissionError(5, "拒绝访问", path)
        if path not in self.hive:
            raise FileNotFoundError(2, "系统找不到指定的文件", path)
        return self._Key(self, path)

    def CreateKeyEx(self, root, path, *a):
        if self._denied(path):
            raise PermissionError(5, "拒绝访问", path)
        self.hive.setdefault(path, {})
        return self._Key(self, path)

    def QueryValueEx(self, k, name):
        if self._denied(k.path):
            raise PermissionError(5, "拒绝访问", k.path)
        vals = self.hive.get(k.path, {})
        if name not in vals:
            raise FileNotFoundError(2, "值不存在", name)
        v = vals[name]
        return (v[0], v[1])

    def SetValueEx(self, k, name, _r, vtype, data):
        self.hive.setdefault(k.path, {})[name] = [data, vtype]

    def DeleteValue(self, k, name):
        vals = self.hive.get(k.path, {})
        if name not in vals:
            raise FileNotFoundError(2, "值不存在", name)
        del vals[name]

    def DeleteKey(self, root, path):
        if path not in self.hive:
            raise FileNotFoundError(2, "键不存在", path)
        del self.hive[path]

    def EnumValue(self, k, i):
        vals = self.hive.get(k.path, {})
        items = list(vals.items())
        if i >= len(items):
            raise OSError(259, "没有更多的数据了")
        name, (data, vtype) = items[i]
        return (name, data, vtype)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def setup():
    fake = FakeWinreg()
    sys.modules["winreg"] = fake
    ifeo = load_module("ifeo_block", os.path.join(SCRIPTS, "ifeo_block.py"))
    ifeo.require_admin = lambda: None          # 测试环境免管理员
    tmp = tempfile.mkdtemp(prefix="ifeo_test_")
    ifeo.backup_path = lambda: os.path.join(tmp, "backup.json")
    return fake, ifeo, tmp


def kp(name):
    return IFEO_ROOT + "\\" + name


def main():
    print("== AF-01：三种前态的逐值恢复 ==")
    fake, ifeo, tmp = setup()
    # 前态 A：键存在、只有 GlobalFlag、无 Debugger（AF-01 反例本体）
    fake.hive[kp("AlibabaProtect.exe")] = {"GlobalFlag": [1, 4]}
    # 前态 B：键不存在
    # 前态 C：外来自 Debugger
    fake.hive[kp("AlibabaProtectCon.exe")] = {"Debugger": ["C:\\other.exe", 1]}
    ifeo.cmd_apply()
    check("A 加桩后 GlobalFlag 仍在", fake.hive[kp("AlibabaProtect.exe")].get("GlobalFlag") == [1, 4])
    check("A 有桩", fake.hive[kp("AlibabaProtect.exe")]["Debugger"][0] == STUB)
    check("B 键被创建", kp("AliProtectUpdate.exe") in fake.hive)
    check("C 未被动过", fake.hive[kp("AlibabaProtectCon.exe")]["Debugger"][0] == "C:\\other.exe")
    ifeo.cmd_remove(assume_yes=True)
    check("A GlobalFlag 恢复", fake.hive[kp("AlibabaProtect.exe")].get("GlobalFlag") == [1, 4])
    check("A 桩被撤除（AF-01 本体）", "Debugger" not in fake.hive[kp("AlibabaProtect.exe")])
    check("B 键已删除", kp("AliProtectUpdate.exe") not in fake.hive)
    check("C 保持原值", fake.hive[kp("AlibabaProtectCon.exe")]["Debugger"][0] == "C:\\other.exe")

    print("== AF-02：部分失败→重试→原态不丢 ==")
    fake, ifeo, tmp = setup()
    fake.hive[kp("AlibabaProtect.exe")] = {"GlobalFlag": [7, 4]}   # 本轮首个目标带原值
    real_set = ifeo.set_debugger
    state = {"n": 0}
    def flaky_set(name, value):
        state["n"] += 1
        if name.endswith("AlibabaProtect.exe") and state["n"] == 1:
            raise PermissionError(5, "第一次拒绝（模拟 HIPS）")
        return real_set(name, value)
    ifeo.set_debugger = flaky_set
    ifeo.cmd_apply()
    check("第一次部分失败后备份已存在", os.path.isfile(ifeo.backup_path()))
    bak1 = json.load(open(ifeo.backup_path(), encoding="utf-8"))
    check("备份记录的是原态（GlobalFlag=7 而非桩）",
          bak1["AlibabaProtect.exe"]["values"].get("GlobalFlag") == [7, 4])
    ifeo.cmd_apply()                      # 重试（失败项这次成功）
    bak2 = json.load(open(ifeo.backup_path(), encoding="utf-8"))
    check("重试未覆盖已记录原态", bak2["AlibabaProtect.exe"]["values"].get("GlobalFlag") == [7, 4])
    ifeo.cmd_remove(assume_yes=True)
    check("重试后 remove：原值完整恢复",
          fake.hive[kp("AlibabaProtect.exe")].get("GlobalFlag") == [7, 4]
          and "Debugger" not in fake.hive[kp("AlibabaProtect.exe")])

    print("== AF-02：备份先行失败 → 零注册表写入 ==")
    fake, ifeo, tmp = setup()
    ifeo.save_backup = lambda entries: (print("  （模拟备份写失败）"), None)[1]
    rc = ifeo.cmd_apply()
    check("apply 返回 1", rc == 1)
    check("假注册表零写入（无任何目标键）",
          not any(p.startswith(IFEO_ROOT) for p in fake.hive))

    print("== AF-02：备份损坏/缺失 → remove 失败关闭 ==")
    for mode in ("corrupt", "missing"):
        fake, ifeo, tmp = setup()
        ifeo.cmd_apply()
        check(mode + ": 拦截已建立", ifeo.get_debugger("AlibabaProtect.exe") == STUB)
        bp = ifeo.backup_path()
        if mode == "corrupt":
            open(bp, "w", encoding="utf-8").write("{ not json")
        else:
            os.unlink(bp)
        rc = ifeo.cmd_remove(assume_yes=True)
        check(mode + ": remove 返回 1", rc == 1)
        check(mode + ": 桩未被自动删除（失败关闭）",
              ifeo.get_debugger("AlibabaProtect.exe") == STUB)

    print("== AF-03：verify_clean 原语三态 ==")
    fake, ifeo, tmp = setup()
    verify = load_module("verify_clean", os.path.join(SCRIPTS, "verify_clean.py"))
    p_exist = r"SYSTEM\X\Exists"
    p_absent = r"SYSTEM\X\Absent"
    p_denied = r"SYSTEM\X\Denied"
    fake.hive[p_exist] = {"v": [1, 4]}
    fake.deny_paths.add(p_denied)
    check("reg_key_exists 存在=True", verify.reg_key_exists(p_exist) is True)
    check("reg_key_exists 不存在=False", verify.reg_key_exists(p_absent) is False)
    check("reg_key_exists 拒绝访问=None", verify.reg_key_exists(p_denied) is None)
    # find_tasks：退出码非零 / 空输出 / 文件夹路径任务
    def fake_run_text(args, timeout=40, with_rc=False):
        if args[1] == "/query":
            if verify.find_tasks.scenario == "rc":
                return ("", 1) if with_rc else ""
            if verify.find_tasks.scenario == "empty":
                return ("", 0) if with_rc else ""
            csv = '"\\\\MyFolder\\\\AliDeepTask","2026/1/1 00:00:00","Ready","x"\r\n'
            return (csv, 0) if with_rc else csv
        return ("", 0) if with_rc else ""
    verify.run_text = fake_run_text
    verify.find_tasks.scenario = "rc"
    check("schtasks 非零退出 → err", verify.find_tasks()[1] is not None)
    verify.find_tasks.scenario = "empty"
    check("schtasks 空输出 → err", verify.find_tasks()[1] is not None)
    verify.find_tasks.scenario = "folder"
    hits, err = verify.find_tasks()
    check("文件夹路径任务被命中", err is None and hits
          and hits[0][0].endswith("AliDeepTask"))
    # enum_processes：快照失败 → None
    verify.kernel32.CreateToolhelp32Snapshot = lambda *a: None
    check("进程快照失败 → None（未知）",
          verify.enum_processes({"x.exe"}) is None)

    print("")
    if FAILURES:
        print("FAILED %d:" % len(FAILURES))
        for f in FAILURES:
            print("  -", f)
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
