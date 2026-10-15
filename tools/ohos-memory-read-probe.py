#!/usr/bin/env python3
"""Check process_vm_readv in an application UID against one owned stopped child.

Requires adjacent ohos-exec-probe.py. Only allocated diagnostic memory is read;
no application/user file is accessed. No filter or production policy is changed.
"""
import ctypes
import importlib.util
import json
import mmap
import os
from pathlib import Path
import platform
import signal

spec = importlib.util.spec_from_file_location("exec_probe", Path(__file__).with_name("ohos-exec-probe.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
LIBC = base.LIBC
LIBC.syscall.restype = ctypes.c_long


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def readv(pid, address, length):
    buffer = ctypes.create_string_buffer(length)
    local = Iovec(ctypes.addressof(buffer), length)
    remote = Iovec(address, length)
    ctypes.set_errno(0)
    count = LIBC.syscall(ctypes.c_long(270), ctypes.c_int(pid), ctypes.byref(local),
        ctypes.c_ulong(1), ctypes.byref(remote), ctypes.c_ulong(1), ctypes.c_ulong(0))
    return {"count": count, "errno": ctypes.get_errno() if count == -1 else 0,
            "bytes": buffer.raw[:max(0, count)].hex()}


def peek_word(pid, address):
    ctypes.set_errno(0)
    word = LIBC.ptrace(2, pid, ctypes.c_void_p(address), None)
    error = ctypes.get_errno()
    return {"count": 8 if error == 0 else -1, "errno": error,
            "bytes": ctypes.c_ulong(word).value.to_bytes(8, "little").hex() if error == 0 else ""}


def main():
    if platform.machine() != "aarch64" or os.getuid() < 10000:
        raise RuntimeError("requires an ARM64 application UID")
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            # An abruptly stopped diagnostic supervisor must not leave this child.
            LIBC.syscall(ctypes.c_long(167), 1, int(signal.SIGKILL), 0, 0, 0)
            short = ctypes.create_string_buffer(b"CHILD_ONLY_PATH\x00")
            long = ctypes.create_string_buffer(b"L" * 1023 + b"\x00")
            pages = mmap.mmap(-1, mmap.PAGESIZE * 2)
            start = ctypes.addressof(ctypes.c_char.from_buffer(pages))
            ctypes.memmove(start + mmap.PAGESIZE - 4, b"END\x00", 4)
            ctypes.memmove(start + mmap.PAGESIZE, b"PEEK_OK\x00", 8)
            protected = LIBC.syscall(ctypes.c_long(226), ctypes.c_void_p(start + mmap.PAGESIZE),
                ctypes.c_size_t(mmap.PAGESIZE), 0)
            if protected != 0:
                raise RuntimeError("cannot create private unreadable page")
            private = mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            private_start = ctypes.addressof(ctypes.c_char.from_buffer(private))
            ctypes.memmove(private_start, b"PRIVATE\x00", 8)
            if LIBC.syscall(ctypes.c_long(226), ctypes.c_void_p(private_start), ctypes.c_size_t(mmap.PAGESIZE), 0) != 0:
                raise RuntimeError("cannot create private protected mapping")
            os.write(writer, json.dumps({"short": ctypes.addressof(short),
                "long": ctypes.addressof(long), "boundary": start + mmap.PAGESIZE - 4,
                "protected": start + mmap.PAGESIZE, "private": private_start,
                "pageSize": mmap.PAGESIZE}).encode())
            os.close(writer)
            base.ptrace(base.TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
        except BaseException:
            os._exit(126)
        os._exit(0)
    os.close(writer)
    result = {"uid": os.getuid(), "pid": pid, "cases": {}}
    try:
        metadata = json.loads(os.read(reader, 4096))
        _, status = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError("owned child did not reach ptrace stop")
        base.ptrace(base.SETOPTIONS, pid, 0x100000)
        result["pageSize"] = metadata["pageSize"]
        result["cases"]["short"] = readv(pid, metadata["short"], 16)
        result["cases"]["long"] = readv(pid, metadata["long"], 1024)
        result["cases"]["page-boundary"] = readv(pid, metadata["boundary"], 4)
        result["cases"]["cross-unreadable-page"] = readv(pid, metadata["boundary"], 16)
        result["cases"]["null"] = readv(pid, 0, 16)
        result["cases"]["shared-protected-page"] = readv(pid, metadata["protected"], 8)
        result["cases"]["ptrace-shared-protected-page"] = peek_word(pid, metadata["protected"])
        result["cases"]["private-protected-page"] = readv(pid, metadata["private"], 8)
        result["cases"]["ptrace-private-protected-page"] = peek_word(pid, metadata["private"])
    finally:
        os.close(reader)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        while True:
            try:
                _, status = os.waitpid(pid, 0)
            except ChildProcessError:
                break
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                break
            base.ptrace(base.CONT, pid, signal.SIGKILL)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
