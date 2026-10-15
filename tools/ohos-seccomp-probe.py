#!/usr/bin/env python3
"""Diagnostic only: test extra seccomp filters in disposable application children.

Run with the signed Python HNP, outside the production directory-control runner.
Never installs a filter in Electron or in this supervising Python process.
Requires adjacent ohos-exec-probe.py. No root, system-policy edits, or user files.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import time

spec = importlib.util.spec_from_file_location("exec_probe", Path(__file__).with_name("ohos-exec-probe.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
LIBC = base.LIBC
LIBC.syscall.restype = ctypes.c_long
ALLOW, TRACE, ERRNO, TRAP = 0x7FFF0000, 0x7FF00000, 0x00050000, 0x00030000
TRACESECCOMP = 0x80


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]


def call(number, *args):
    ctypes.set_errno(0)
    result = LIBC.syscall(ctypes.c_long(number), *args)
    return {"result": result, "errno": ctypes.get_errno() if result == -1 else 0}


def run(mode, timeout):
    reader, writer = os.pipe()
    started = time.monotonic()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        result = {"mode": mode, "pid": os.getpid(), "uid": os.getuid()}
        stage = "start"
        try:
            if mode.startswith("trace-"):
                stage = "traceme"
                base.ptrace(base.TRACEME, 0)
                os.kill(os.getpid(), signal.SIGSTOP)
            if mode.startswith("query-"):
                action = ctypes.c_uint(TRACE if mode == "query-trace" else ALLOW)
                result["query"] = call(277, 2, 0, ctypes.byref(action))
            else:
                stage = "no_new_privs"
                result["noNewPrivs"] = call(167, 38, 1, 0, 0, 0)
                if result["noNewPrivs"]["result"] != 0:
                    raise RuntimeError("no_new_privs failed")
                if mode.startswith("errno-") or "-errno-" in mode:
                    action = ERRNO | 13
                elif mode.startswith("trap-"):
                    action = TRAP
                elif mode.startswith("trace-") and "-allow-" not in mode:
                    action = TRACE | (0x1234 if "-tagged-" in mode else 0)
                else:
                    action = ALLOW
                if mode.startswith("trap-"):
                    result["trapSignals"] = []
                    signal.signal(signal.SIGSYS, lambda number, frame: result["trapSignals"].append(number))
                # Filter syscall number only, never a pathname pointer. All
                # process/file policies inherited from the platform remain.
                instructions = (Filter * 4)(Filter(0x20, 0, 0, 0),
                    Filter(0x15, 0, 1, 173), Filter(0x06, 0, 0, action),
                    Filter(0x06, 0, 0, ALLOW))
                program = Program(len(instructions), instructions)
                stage = "install"
                result["install"] = (call(167, 22, 2, ctypes.byref(program), 0, 0)
                    if mode.endswith("prctl") else call(277, 1, 0, ctypes.byref(program)))
                if result["install"]["result"] == 0:
                    if mode in ("errno-exec-seccomp", "trap-exec-seccomp"):
                        stage = "exec-private-bash-python"
                        code = ("import ctypes,json,os;lib=ctypes.CDLL(None,use_errno=True);"
                            "value=lib.syscall(173);error=ctypes.get_errno();"
                            f"os.write({writer},json.dumps({{'mode':{mode!r},'afterExec':True,"
                            "'result':value,'errno':error,'uid':os.getuid()}).encode())")
                        os.set_inheritable(writer, True)
                        environment = dict(os.environ)
                        environment.pop("BASH_ENV", None)
                        environment.pop("ENV", None)
                        os.execve("/data/app/bash.org/bash_5.3/bin/bash",
                            ["bash", "--noprofile", "--norc", "-c", 'exec -- "$@"', "seccomp-inherit",
                             "/data/app/python.org/python_3.12.9/bin/python3", "-c", code], environment)
                    stage = "getppid"
                    result["targetCalls"] = [call(173) for _ in range(10)]
                    result["otherCall"] = call(172)
        except BaseException as error:
            result["error"] = {"stage": stage, "errno": getattr(error, "errno", None), "message": str(error)}
        os.write(writer, json.dumps(result).encode())
        os._exit(0)
    os.close(writer)
    events, other_stops, terminal = [], [], False
    result = {"mode": mode, "pid": pid, "exitCode": None, "signal": None,
              "timedOut": False, "events": events, "otherStops": other_stops, "syscallStops": 0}
    try:
        initial = mode.startswith("trace-")
        while not terminal:
            if time.monotonic() - started >= timeout:
                result["timedOut"] = True
                break
            got, status = os.waitpid(pid, os.WNOHANG)
            if not got:
                time.sleep(0.001)
                continue
            if os.WIFEXITED(status):
                result["exitCode"] = os.WEXITSTATUS(status)
                terminal = True
            elif os.WIFSIGNALED(status):
                result["signal"] = os.WTERMSIG(status)
                terminal = True
            elif os.WIFSTOPPED(status):
                stopped, event = os.WSTOPSIG(status), status >> 16
                if initial:
                    if stopped != signal.SIGSTOP:
                        raise RuntimeError("unexpected initial stop")
                    base.ptrace(base.SETOPTIONS, pid, TRACESECCOMP | base.SYSCALL_OPTIONS)
                    initial = False
                elif event:
                    events.append(event)
                elif stopped == (signal.SIGTRAP | 0x80):
                    result["syscallStops"] += 1
                else:
                    other_stops.append(stopped)
                resume = base.SYSCALL if "-syscall-" in mode else base.CONT
                synthetic = event or stopped in (signal.SIGSTOP, signal.SIGTRAP, signal.SIGTRAP | 0x80)
                base.ptrace(resume, pid, 0 if synthetic else stopped)
    except BaseException as error:
        result["tracerError"] = {"errno": getattr(error, "errno", None), "message": str(error)}
    finally:
        if not terminal:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while True:
                try:
                    _, status = os.waitpid(pid, 0)
                except InterruptedError:
                    continue
                except ChildProcessError:
                    break
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    break
                try:
                    base.ptrace(base.CONT, pid, signal.SIGKILL)
                except OSError:
                    pass
        data = os.read(reader, 16384)
        os.close(reader)
    result["child"] = json.loads(data) if data else None
    result["elapsedMs"] = round((time.monotonic() - started) * 1000, 2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=8)
    parser.add_argument("--mode", nargs="+", choices=["query-allow", "query-trace",
        "allow-seccomp", "allow-prctl", "errno-seccomp", "errno-prctl",
        "trace-seccomp", "trace-prctl", "trace-syscall-seccomp", "trace-syscall-prctl",
        "trace-tagged-seccomp", "trace-allow-seccomp", "trace-errno-seccomp",
        "trap-seccomp", "trap-exec-seccomp", "errno-exec-seccomp"])
    args = parser.parse_args()
    if platform.machine() != "aarch64" or os.getuid() < 10000 or args.timeout <= 0:
        parser.error("requires an ARM64 application UID and positive timeout")
    modes = args.mode or ["query-allow", "query-trace", "allow-seccomp", "allow-prctl",
             "errno-seccomp", "errno-prctl", "trace-seccomp", "trace-prctl"]
    print(json.dumps({"schema": "yj-ohos-seccomp-probe-v1", "uid": os.getuid(),
        "kernel": platform.uname()._asdict(), "cases": [run(mode, args.timeout) for mode in modes]}))


if __name__ == "__main__":
    main()
