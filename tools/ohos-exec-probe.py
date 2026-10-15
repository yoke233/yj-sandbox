#!/usr/bin/env python3
"""Diagnostic only: compare direct exec with minimal CONT/SYSCALL tracing.

Run using the application's signed Python HNP, outside the directory-control
runner. No policy changes, detach, retries, user-data reads, or external tools.
"""
import argparse
import ctypes
import errno
import json
import os
import platform
import signal
import time

TRACEME, CONT, SYSCALL = 0, 7, 24
SETOPTIONS = 0x4200
SYSCALL_OPTIONS = 1 | 16 | 0x100000  # TRACESYSGOOD, TRACEEXEC, EXITKILL
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.restype = ctypes.c_long
LIBC.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]


def ptrace(request, pid, data=0):
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, None, ctypes.c_void_p(data))
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error))
    return result


def run_case(mode, name, argv, timeout):
    environment = dict(os.environ)
    # Noninteractive Bash still sources BASH_ENV even with --noprofile/--norc.
    environment.pop("BASH_ENV", None)
    environment.pop("ENV", None)
    pipes = [os.pipe() for _ in range(3)]  # stdout, stderr, exec failure
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        stage = "child_setup"
        try:
            for read_fd, _ in pipes:
                os.close(read_fd)
            os.dup2(pipes[0][1], 1)
            os.dup2(pipes[1][1], 2)
            for _, write_fd in pipes[:2]:
                if write_fd not in (1, 2):
                    os.close(write_fd)
            os.chdir("/")
            if mode != "none":
                stage = "traceme"
                ptrace(TRACEME, 0)
                os.kill(os.getpid(), signal.SIGSTOP)
            stage = "execve"
            os.execve(argv[0], argv, environment)
        except BaseException as error:
            payload = {"stage": stage, "errno": getattr(error, "errno", None), "error": str(error)}
            os.write(pipes[2][1], json.dumps(payload).encode())
        os._exit(126)

    buffers = [bytearray(), bytearray(), bytearray()]
    for read_fd, write_fd in pipes:
        os.close(write_fd)
        os.set_blocking(read_fd, False)
    result = {"mode": mode, "target": name, "argv": argv, "pid": pid,
              "exit_code": None, "signal": None, "timed_out": False,
              "syscall_stops": 0, "exec_events": 0, "other_stops": [],
              "tracer_error": None}
    initial = mode != "none"
    terminal = False

    def drain():
        for index, (read_fd, _) in enumerate(pipes):
            while True:
                try:
                    chunk = os.read(read_fd, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                # Drain everything to prevent pipe deadlocks, retain bounded output.
                remaining = max(0, 16384 - len(buffers[index]))
                buffers[index].extend(chunk[:remaining])

    try:
        while not terminal:
            drain()
            if time.monotonic() - start >= timeout:
                result["timed_out"] = True
                break
            try:
                got, status = os.waitpid(pid, os.WNOHANG)
            except InterruptedError:
                continue
            if not got:
                time.sleep(0.001)
                continue
            if os.WIFEXITED(status):
                result["exit_code"] = os.WEXITSTATUS(status)
                terminal = True
            elif os.WIFSIGNALED(status):
                result["signal"] = os.WTERMSIG(status)
                terminal = True
            elif os.WIFSTOPPED(status):
                stop = os.WSTOPSIG(status)
                event = status >> 16
                if initial:
                    if stop != signal.SIGSTOP:
                        raise RuntimeError("unexpected initial stop: %d" % stop)
                    if mode == "syscall":
                        ptrace(SETOPTIONS, pid, SYSCALL_OPTIONS)
                    initial = False
                elif event == 4:
                    result["exec_events"] += 1
                elif stop == (signal.SIGTRAP | 0x80):
                    result["syscall_stops"] += 1
                elif stop != signal.SIGTRAP:
                    if len(result["other_stops"]) < 32:
                        result["other_stops"].append(stop)
                # CONT's successful exec produces a plain SIGTRAP; consume only
                # synthetic traps/stops and forward genuine delivery signals.
                deliver = 0 if stop in (signal.SIGSTOP, signal.SIGTRAP, signal.SIGTRAP | 0x80) else stop
                ptrace(SYSCALL if mode == "syscall" else CONT, pid, deliver)
    except BaseException as error:
        result["tracer_error"] = {"errno": getattr(error, "errno", None), "error": str(error)}
    finally:
        if not terminal:
            # Never waitpid(-1), kill a process group, or touch unrelated PIDs.
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
                    ptrace(CONT, pid, signal.SIGKILL)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        result["cleanup_error"] = str(error)
        drain()
        for read_fd, _ in pipes:
            os.close(read_fd)
    result["stdout"] = buffers[0].decode("utf-8", "replace")
    result["stderr"] = buffers[1].decode("utf-8", "replace")
    result["exec_error"] = json.loads(buffers[2]) if buffers[2] else None
    result["elapsed_ms"] = round((time.monotonic() - start) * 1000)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", required=True, help="Absolute path to application's private signed Bash")
    parser.add_argument("--timeout", type=float, default=8.0, help="Seconds per case")
    args = parser.parse_args()
    if not os.path.isabs(args.bash) or args.timeout <= 0:
        parser.error("--bash must be absolute and --timeout positive")
    targets = [("private_bash", [args.bash, "--noprofile", "--norc", "-c", "printf YJ_EXEC_PROBE_OK"]),
               ("direct_toybox", ["/system/bin/toybox", "--help"]),
               ("system_ls", ["/system/bin/ls", "-d", "/system/bin/ls"])]
    cases = [run_case(mode, name, argv, args.timeout)
             for mode in ("none", "cont", "syscall") for name, argv in targets]
    print(json.dumps({"schema": "yj-ohos-exec-probe-v1", "uid": os.getuid(),
                      "machine": platform.machine(), "cases": cases}, ensure_ascii=True))


if __name__ == "__main__":
    main()
