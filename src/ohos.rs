//! OHOS ARM64 pure-ptrace accidental-file-access guard.
//!
//! This is deliberately not hostile-code isolation. Pathname, FD, shared-memory,
//! and rename check/continue races remain; see the README. No seccomp is used.
use crate::ohos_policy::{Access, OhosDirectoryPolicy, SyscallPhase, resolve};
use crate::{CaptureResult, ResolvedWindowsSandboxPermissions, WindowsSandboxCancellationToken};
use anyhow::{Context, Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::borrow::Cow;
use std::ffi::{CString, OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

type Pid = libc::pid_t;
const TRACEME: i32 = 0;
const PEEKDATA: i32 = 2;
const POKEDATA: i32 = 5;
const SYSCALL: i32 = 24;
const SETOPTIONS: i32 = 0x4200;
const GETEVENTMSG: i32 = 0x4201;
const GETREGSET: i32 = 0x4204;
const SETREGSET: i32 = 0x4205;
const NT_PRSTATUS: usize = 1;
const NT_ARM_SYSTEM_CALL: usize = 0x404;
const OPTIONS: usize = 1 | 2 | 4 | 8 | 16 | 64 | 0x100000; // syscall-good, fork/vfork/clone/exec/exit, EXITKILL
const WALL: i32 = 0x40000000;
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const PATH_MAX: usize = 4096;
static CANCELLED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    #[link_name = "ptrace"]
    fn c_ptrace(request: libc::c_int, ...) -> libc::c_long;
}

fn ptrace(request: i32, pid: Pid, addr: usize, data: usize) -> Result<libc::c_long> {
    unsafe {
        *libc::__errno_location() = 0;
        let result = c_ptrace(request, pid, addr, data);
        if result == -1 && *libc::__errno_location() != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("ptrace {request:#x} pid {pid}"));
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Registers { x: [u64; 31], sp: u64, pc: u64, pstate: u64 }

fn regset<T>(request: i32, pid: Pid, note: usize, value: &mut T) -> Result<()> {
    let mut io = libc::iovec { iov_base: (value as *mut T).cast(), iov_len: std::mem::size_of::<T>() };
    ptrace(request, pid, note, (&mut io as *mut libc::iovec) as usize)?;
    ensure!(io.iov_len == std::mem::size_of::<T>(), "short register set {note:#x}: {}", io.iov_len);
    Ok(())
}

fn skip(pid: Pid, regs: &mut Registers) -> Result<()> {
    let mut nr: i32 = -1;
    regset(SETREGSET, pid, NT_ARM_SYSTEM_CALL, &mut nr)?;
    regs.x[8] = u64::MAX;
    regset(SETREGSET, pid, NT_PRSTATUS, regs)
}

extern "C" fn terminate(_: i32) { CANCELLED.store(true, Ordering::Relaxed); }

struct SignalHandlers(Vec<(i32, libc::sigaction)>);
impl SignalHandlers {
    fn install() -> Result<Self> {
        CANCELLED.store(false, Ordering::Relaxed);
        let mut handlers = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                let mut old: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = terminate as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                ensure!(libc::sigaction(signal, &action, &mut old) == 0, "cannot install termination handler: {}", std::io::Error::last_os_error());
                handlers.0.push((signal, old));
            }
        }
        Ok(handlers)
    }
}
impl Drop for SignalHandlers {
    fn drop(&mut self) { for (signal, old) in &self.0 { unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()); } } }
}

/// Every traced TID is owned, including children which leave the process group.
/// EXITKILL is also installed on every tracee, so SIGKILL of the tracer fails closed.
struct OwnedTracees { root: Pid, live: HashSet<Pid> }
impl OwnedTracees {
    fn new(root: Pid) -> Self { Self { root, live: HashSet::from([root]) } }
    fn kill(&self) {
        if self.live.is_empty() { return; }
        unsafe {
            libc::kill(-self.root, libc::SIGKILL);
            for pid in &self.live { libc::kill(*pid, libc::SIGKILL); }
        }
    }

    fn adopt_newborn(&mut self, pid: Pid) -> Result<()> {
        // waitpid(-1) may report the child's initial stop before its parent's
        // fork event. Verify tracer + ancestry before taking ownership.
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name)?.trim().parse::<Pid>().ok());
        ensure!(field("TracerPid:") == Some(unsafe { libc::getpid() })
            && (field("PPid:").is_some_and(|parent| self.live.contains(&parent))
                || field("Tgid:").is_some_and(|group| self.live.contains(&group))),
            "unexpected non-owned tracee {pid}; use the OHOS runner in its own process");
        self.live.insert(pid);
        Ok(())
    }
}
impl Drop for OwnedTracees {
    fn drop(&mut self) {
        self.kill();
        // A failure may occur at a pending fork event, before its child has
        // entered the normal ownership map. Discover and reap that child too.
        let mut pending: Vec<_> = self.live.iter().copied().collect();
        while let Some(pid) = pending.pop() {
            loop {
                let mut status = 0;
                let got = unsafe { libc::waitpid(pid, &mut status, WALL) };
                if got < 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
                    break;
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) { break; }
                if matches!((status as u32) >> 16, 1..=3) {
                    let mut child: libc::c_ulong = 0;
                    if ptrace(GETEVENTMSG,pid,0,(&mut child as *mut libc::c_ulong) as usize).is_ok() {
                        let child = child as Pid;
                        if child > 0 && self.live.insert(child) {
                            pending.push(child);
                            unsafe { libc::kill(child,libc::SIGKILL); }
                        }
                    }
                }
                let _ = ptrace(SYSCALL,pid,0,libc::SIGKILL as usize);
            }
        }
    }
}

#[derive(Default)]
struct Task { phase: SyscallPhase, newborn: bool }

fn initial_stop(pid: Pid) -> Result<()> {
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        ensure!(result == pid && libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP,
            "owned child did not enter TRACEME stop (status {status:#x})");
        ptrace(SETOPTIONS, pid, 0, OPTIONS)?;
        return Ok(());
    }
}

fn peek(pid: Pid, address: u64) -> Result<u64> { Ok(ptrace(PEEKDATA, pid, address as usize, 0)? as u64) }

struct Guard<'a> {
    policy: &'a OhosDirectoryPolicy,
    path_buffer: [u8; PATH_MAX],
    // Zero disables bulk reads for this run if the interface is unavailable.
    vm_page_size: usize,
    stdio: [Option<PathBuf>; 3],
}
impl<'a> Guard<'a> {
    fn new(policy: &'a OhosDirectoryPolicy, pid: Pid) -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        Self { policy, path_buffer: [0; PATH_MAX], vm_page_size: if page_size > 0 { page_size as usize } else { 0 }, stdio: std::array::from_fn(|fd| std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()) }
    }

    fn string(&mut self, pid: Pid, address: u64) -> Result<PathBuf> {
        ensure!(address != 0, "null pathname");
        let mut count = 0;
        let mut bulk = self.vm_page_size != 0;
        while count < PATH_MAX {
            let current = address.checked_add(count as u64).context("pathname address overflow")?;
            let mut read = 0;
            if bulk {
                // OHOS may fail the whole read if the remote iovec crosses into
                // an unreadable page, even when an earlier byte contains NUL.
                let length = (PATH_MAX - count)
                    .min(self.vm_page_size - (current % self.vm_page_size as u64) as usize)
                    .min((u64::MAX - current).min((PATH_MAX - 1) as u64) as usize + 1);
                let local = libc::iovec { iov_base: self.path_buffer[count..].as_mut_ptr().cast(), iov_len: length };
                let remote = libc::iovec { iov_base: current as usize as *mut libc::c_void, iov_len: length };
                let result = unsafe { libc::syscall(270, pid, &local as *const libc::iovec, 1usize, &remote as *const libc::iovec, 1usize, 0usize) };
                if result > 0 {
                    ensure!(result as usize <= length, "invalid remote pathname read length");
                    read = result as usize;
                } else {
                    if result < 0 && matches!(std::io::Error::last_os_error().raw_os_error(),Some(libc::ENOSYS | libc::EPERM | libc::EACCES)) {
                        self.vm_page_size = 0;
                    }
                    // Preserve the original reader on bulk failure; ptrace may
                    // inspect mappings that the bulk interface cannot read.
                    // Do not retry the failed bulk interface for each word.
                    bulk = false;
                }
            }
            if read == 0 {
                let aligned = current & !7;
                let bytes = peek(pid, aligned)?.to_ne_bytes();
                let offset = (current - aligned) as usize;
                read = (bytes.len() - offset).min(PATH_MAX - count);
                self.path_buffer[count..count+read].copy_from_slice(&bytes[offset..offset+read]);
            }
            // Only bytes returned by this read are initialized pathname data.
            if let Some(nul) = self.path_buffer[count..count+read].iter().position(|byte| *byte == 0) {
                return Ok(PathBuf::from(OsString::from_vec(self.path_buffer[..count+nul].to_vec())));
            }
            count += read;
        }
        bail!("pathname exceeds PATH_MAX")
    }

    fn fd_link(&self, pid: Pid, fd: i32) -> Result<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).with_context(|| format!("cannot resolve fd {fd}"))
    }

    fn proc_path<'p>(&self, pid: Pid, path: &'p Path) -> Cow<'p,Path> {
        if let Ok(tail) = path.strip_prefix("/proc/thread-self") { return Cow::Owned(PathBuf::from(format!("/proc/{pid}/task/{pid}")).join(tail)); }
        if let Ok(tail) = path.strip_prefix("/proc/self") { return Cow::Owned(PathBuf::from(format!("/proc/{pid}")).join(tail)); }
        if let Ok(tail) = path.strip_prefix("/dev/fd") { return Cow::Owned(PathBuf::from(format!("/proc/{pid}/fd")).join(tail)); }
        for (alias, fd) in [("/dev/stdin",0),("/dev/stdout",1),("/dev/stderr",2)] {
            if path == Path::new(alias) { return Cow::Owned(PathBuf::from(format!("/proc/{pid}/fd/{fd}"))); }
        }
        Cow::Borrowed(path)
    }

    fn policy_proc_path<'p>(&self, pid: Pid, path: &'p Path) -> Cow<'p,Path> {
        if path.starts_with("/proc") {
            for (actual, alias) in [(format!("/proc/{pid}/task/{pid}"), "/proc/thread-self"), (format!("/proc/{pid}"), "/proc/self")] {
                if let Ok(tail) = path.strip_prefix(actual) { return Cow::Owned(PathBuf::from(alias).join(tail)); }
            }
        }
        Cow::Borrowed(path)
    }

    fn checked_path(&self, pid: Pid, path: &Path, write: bool, follow: bool, tree: bool) -> Result<()> {
        let actual = self.proc_path(pid, path);
        let physical = resolve(&actual, follow)?;
        let resolved = self.policy_proc_path(pid, &physical);
        let logical = self.policy_proc_path(pid, path);
        ensure!(self.policy.allows(&logical, &resolved, write), "{} {}", if write { "write" } else { "read" }, path.display());
        ensure!(!tree || !self.policy.protects_descendant(&logical, &resolved), "protected descendant of {}", path.display());
        Ok(())
    }
    fn checked_metadata(&self, pid: Pid, path: &Path, follow: bool) -> Result<()> {
        let actual = self.proc_path(pid, path);
        let physical = resolve(&actual, follow)?;
        let resolved = self.policy_proc_path(pid, &physical);
        let logical = self.policy_proc_path(pid, path);
        ensure!(self.policy.allows_metadata(&logical, &resolved), "metadata {}", path.display());
        Ok(())
    }


    fn absolute_path(&mut self, pid: Pid, dirfd: i32, address: u64) -> Result<PathBuf> {
        let path = self.string(pid,address)?;
        if path.is_absolute() || path.as_os_str().is_empty() { return Ok(path); }
        let base = if dirfd == AT_FDCWD { std::fs::read_link(format!("/proc/{pid}/cwd")).context("cannot resolve tracee cwd")? } else { self.fd_link(pid,dirfd)? };
        ensure!(base.is_absolute(),"dirfd is not a filesystem directory");
        Ok(base.join(path))
    }

    fn path(&mut self, pid: Pid, dirfd: i32, address: u64, write: bool, follow: bool, empty: bool, tree: bool) -> Result<()> {
        let path = self.absolute_path(pid,dirfd,address)?;
        if path.as_os_str().is_empty() {
            ensure!(empty,"empty pathname without AT_EMPTY_PATH");
            return self.fd(pid,dirfd,write);
        }
        self.checked_path(pid,&path,write,follow,tree)
    }
    fn metadata(&mut self, pid: Pid, dirfd: i32, address: u64, follow: bool, empty: bool) -> Result<()> {
        let path = self.absolute_path(pid,dirfd,address)?;
        if path.as_os_str().is_empty() {
            ensure!(empty,"empty pathname without AT_EMPTY_PATH");
            if dirfd == AT_FDCWD {
                let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).context("cannot resolve tracee cwd")?;
                return self.checked_metadata(pid,&cwd,true);
            }
            return self.fd_access(pid,dirfd,false,true);
        }
        self.checked_metadata(pid,&path,follow)
    }


    fn exec(&mut self, pid: Pid, dirfd: i32, address: u64, flags: u64) -> Result<()> {
        let path = self.absolute_path(pid,dirfd,address)?;
        let image = if path.as_os_str().is_empty() {
            ensure!(flags & AT_EMPTY_PATH != 0,"empty exec pathname without AT_EMPTY_PATH");
            self.fd(pid,dirfd,false)?;
            PathBuf::from(format!("/proc/{pid}/fd/{dirfd}"))
        } else {
            self.checked_path(pid,&path,false,flags & AT_SYMLINK_NOFOLLOW == 0,false)?;
            self.proc_path(pid,&path).into_owned()
        };
        self.exec_image(pid,&image,0)
    }

    fn fd_is_read_only(pid: Pid, fd: i32) -> Result<bool> {
        let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))
            .context("cannot inspect shared mapping FD access mode")?;
        let flags = info.lines().find_map(|line| line.strip_prefix("flags:"))
            .context("shared mapping FD access mode is unavailable")?;
        let flags = u64::from_str_radix(flags.trim(),8).context("invalid FD access mode")?;
        Ok(flags & libc::O_ACCMODE as u64 == libc::O_RDONLY as u64)
    }

    // ELF PT_INTERP and shebang interpreters are read inside exec, without an
    // observable open syscall. Check those implicit reads before allowing exec.
    fn exec_image(&self, pid: Pid, image: &Path, depth: usize) -> Result<()> {
        use std::os::unix::fs::FileExt;
        ensure!(depth < 5,"interpreter recursion exceeds supported depth");
        let file = match std::fs::File::open(image) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()), // preserve exec ENOENT
            Err(error) => return Err(error).context("cannot inspect executable interpreter"),
        };
        let mut header = [0u8;256];
        let count = file.read_at(&mut header,0)?;
        let interpreter = if header[..count].starts_with(b"#!") {
            let line = &header[2..count];
            let begin = line.iter().position(|byte| !matches!(*byte,b' ' | b'\t')).unwrap_or(line.len());
            let end = line[begin..].iter().position(|byte| matches!(*byte,b' ' | b'\t' | b'\n' | b'\r' | 0)).map_or(line.len(),|end| begin + end);
            Some(PathBuf::from(OsStr::from_bytes(&line[begin..end])))
        } else if count >= 64 && header.starts_with(b"\x7fELF") {
            ensure!(header[4] == 2 && header[5] == 1,"unsupported non-ELF64/little-endian executable");
            let phoff = u64::from_le_bytes(header[32..40].try_into()?);
            let phsize = u16::from_le_bytes(header[54..56].try_into()?) as u64;
            let phnum = u16::from_le_bytes(header[56..58].try_into()?) as u64;
            ensure!(phsize >= 56 && phnum <= 1024,"unsupported executable program headers");
            let mut interpreter = None;
            let mut program_header = [0u8;56];
            for index in 0..phnum {
                let offset = phoff.checked_add(index.checked_mul(phsize).context("program header overflow")?).context("program header overflow")?;
                file.read_exact_at(&mut program_header,offset)?;
                if u32::from_le_bytes(program_header[..4].try_into()?) == 3 {
                    ensure!(interpreter.is_none(),"multiple ELF interpreters");
                    let offset = u64::from_le_bytes(program_header[8..16].try_into()?);
                    let size = u64::from_le_bytes(program_header[32..40].try_into()?) as usize;
                    ensure!(size > 1 && size <= PATH_MAX,"invalid ELF interpreter length");
                    let mut bytes = [0u8;PATH_MAX];
                    file.read_exact_at(&mut bytes[..size],offset)?;
                    ensure!(bytes[size-1] == 0 && !bytes[..size-1].contains(&0),"invalid ELF interpreter pathname");
                    interpreter = Some(PathBuf::from(OsStr::from_bytes(&bytes[..size-1])));
                }
            }
            interpreter
        } else { None }; // ENOEXEC text is Bash's ordinary script fallback.
        if let Some(interpreter) = interpreter {
            ensure!(interpreter.is_absolute(),"interpreter pathname must be absolute");
            self.checked_path(pid,&interpreter,false,true,false)?;
            self.exec_image(pid,&self.proc_path(pid,&interpreter),depth+1)?;
        }
        Ok(())
    }

    fn fd(&self, pid: Pid, fd: i32, write: bool) -> Result<()> {
        self.fd_access(pid,fd,write,false)
    }

    fn fd_access(&self, pid: Pid, fd: i32, write: bool, metadata: bool) -> Result<()> {
        let path = self.fd_link(pid, fd)?;
        // Only the original, intentionally inherited stdio is exempt. A later
        // dup2 of a real file is checked using that file's actual pathname.
        if (0..3).contains(&fd) && self.stdio[fd as usize].as_ref() == Some(&path) { return Ok(()); }
        let bytes = path.as_os_str().as_bytes();
        if bytes.starts_with(b"pipe:[") || bytes.starts_with(b"socket:[") || bytes.starts_with(b"anon_inode:") || bytes.starts_with(b"/memfd:") || bytes.starts_with(b"memfd:") { return Ok(()); }
        ensure!(path.is_absolute(), "unsupported fd {fd}: {}", path.display());
        let path = if let Some(bytes) = bytes.strip_suffix(b" (deleted)") {
            // A live filename may itself end with this text. Strip only the
            // kernel's missing/deleted-link suffix, not an existing pathname.
            if std::fs::symlink_metadata(&path).is_err() { PathBuf::from(OsStr::from_bytes(bytes)) } else { path }
        } else { path };
        if metadata { self.checked_metadata(pid,&path,false) }
        else { self.checked_path(pid, &path, write, true, false) }
    }

    fn open(&mut self, pid: Pid, dirfd: i32, address: u64, flags: u64) -> Result<()> {
        // O_PATH is a metadata handle; all later FD operations are checked again.
        if flags & libc::O_PATH as u64 != 0 {
            return self.metadata(pid,dirfd,address,flags & libc::O_NOFOLLOW as u64 == 0,false);
        }
        let write = flags & 3 != 0 || flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u64 != 0
            || flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64;
        self.path(pid,dirfd,address,write,flags & libc::O_NOFOLLOW as u64 == 0,false,false)
    }

    /// AArch64 uses asm-generic syscall numbers: there are no legacy open/stat.
    /// Non-filesystem syscalls take this match's allocation-free default path.
    fn syscall(&mut self, pid: Pid, nr: u64, a: &[u64; 31]) -> Result<Option<i32>> {
        match nr {
            // Native Node/libuv can fall back when io_uring is unavailable. Do
            // not return EPERM (some consumers treat that as a fatal setup error).
            425..=427 | 435 => return Ok(Some(libc::ENOSYS)), // io_uring, clone3 -> traced clone fallback
            56 => self.open(pid,a[0] as i32,a[1],a[2])?,
            437 => { // openat2: decode only the published open_how fields
                ensure!(a[3] >= 24 && a[3] <= 4096,"unsupported open_how size");
                let flags = peek(pid,a[2])?;
                let resolution = peek(pid,a[2].checked_add(16).context("open_how address overflow")?)?;
                ensure!(resolution & 0x10 == 0,"openat2 RESOLVE_IN_ROOT changes pathname semantics and is unsupported");
                self.open(pid,a[0] as i32,a[1],flags)?;
            }
            63 | 65 | 67 | 69 | 61 | 44 | 286 | 451 => self.fd(pid,a[0] as i32,false)?,
            80 => self.fd_access(pid,a[0] as i32,false,true)?, // fstat
            64 | 66 | 68 | 70 | 75 | 46 | 47 | 52 | 55 | 287 => self.fd(pid,a[0] as i32,true)?,
            71 => { self.fd(pid,a[0] as i32,true)?; self.fd(pid,a[1] as i32,false)?; } // sendfile
            76 | 285 => { self.fd(pid,a[0] as i32,false)?; self.fd(pid,a[2] as i32,true)?; } // splice, copy_file_range
            77 => { self.fd(pid,a[0] as i32,false)?; self.fd(pid,a[1] as i32,true)?; } // tee
            222 => { // Read-only FDs cannot gain shared write access through mprotect.
                if a[3] & libc::MAP_ANONYMOUS as u64 == 0 {
                    let shared = a[3] & 3 == libc::MAP_SHARED as u64 || a[3] & 3 == 3;
                    let write = shared && (a[2] & libc::PROT_WRITE as u64 != 0 ||
                        !Self::fd_is_read_only(pid,a[4] as i32)?);
                    self.fd(pid,a[4] as i32,write)?;
                }
            }
            43 => self.path(pid,AT_FDCWD,a[0],false,true,false,false)?, // statfs
            48 => self.metadata(pid,a[0] as i32,a[1],true,false)?, // faccessat queries permissions, never grants I/O
            78 => self.metadata(pid,a[0] as i32,a[1],false,true)?, // readlinkat exposes link metadata, never directory contents
            49 => self.path(pid,AT_FDCWD,a[0],false,true,false,false)?, // chdir
            50 => self.fd(pid,a[0] as i32,false)?, // fchdir
            45 => self.path(pid,AT_FDCWD,a[0],true,true,false,false)?, // truncate
            34 => self.path(pid,a[0] as i32,a[1],true,false,false,false)?, // mkdirat
            35 => self.path(pid,a[0] as i32,a[1],true,false,false,true)?, // unlinkat
            36 => self.path(pid,a[1] as i32,a[2],true,false,false,false)?, // symlinkat (target is just stored text)
            37 => { // hardlink source needs write too: otherwise an RW alias defeats RO.
                self.path(pid,a[0] as i32,a[1],true,a[4] & 0x400 != 0,a[4] & AT_EMPTY_PATH != 0,false)?;
                self.path(pid,a[2] as i32,a[3],true,false,false,false)?;
            }
            38 | 276 => { // renameat / renameat2
                self.path(pid,a[0] as i32,a[1],true,false,false,true)?;
                self.path(pid,a[2] as i32,a[3],true,false,false,true)?;
            }
            53 => self.path(pid,a[0] as i32,a[1],true,true,false,false)?, // fchmodat
            54 => self.path(pid,a[0] as i32,a[1],true,a[4] & AT_SYMLINK_NOFOLLOW == 0,a[4] & AT_EMPTY_PATH != 0,false)?,
            79 => self.metadata(pid,a[0] as i32,a[1],a[3] & AT_SYMLINK_NOFOLLOW == 0,a[3] & AT_EMPTY_PATH != 0)?, // newfstatat
            88 => { // utimensat NULL pathname operates on dirfd
                if a[1] == 0 { self.fd(pid,a[0] as i32,true)?; }
                else { self.path(pid,a[0] as i32,a[1],true,a[3] & AT_SYMLINK_NOFOLLOW == 0,a[3] & AT_EMPTY_PATH != 0,false)?; }
            }
            221 => self.exec(pid,AT_FDCWD,a[0],0)?,
            281 => self.exec(pid,a[0] as i32,a[1],a[4])?,
            291 => self.metadata(pid,a[0] as i32,a[1],a[2] & AT_SYMLINK_NOFOLLOW == 0,a[2] & AT_EMPTY_PATH != 0)?, // statx
            439 => self.metadata(pid,a[0] as i32,a[1],a[3] & AT_SYMLINK_NOFOLLOW == 0,a[3] & AT_EMPTY_PATH != 0)?, // faccessat2
            452 => self.path(pid,a[0] as i32,a[1],true,a[3] & AT_SYMLINK_NOFOLLOW == 0,a[3] & AT_EMPTY_PATH != 0,false)?, // fchmodat2
            5 | 6 | 14 | 15 => self.path(pid,AT_FDCWD,a[0],true,nr == 5 || nr == 14,false,false)?,
            8 | 9 | 11 | 12 => self.path(pid,AT_FDCWD,a[0],false,nr == 8 || nr == 11,false,false)?,
            7 | 16 => self.fd(pid,a[0] as i32,true)?, // fsetxattr/fremovexattr
            10 | 13 => self.fd(pid,a[0] as i32,false)?,
            27 => self.path(pid,AT_FDCWD,a[1],false,true,false,false)?, // inotify_add_watch
            29 => { // ioctl on disk objects can mutate without a pathname.
                if a[1] == 0x40049409 { // FICLONE: independent copy-on-write data, not a hardlink.
                    self.fd(pid,a[0] as i32,true)?;
                    self.fd(pid,a[2] as i32,false)?;
                } else if a[1] == 0x4020940d { // FICLONERANGE source descriptor in struct file_clone_range.
                    self.fd(pid,a[0] as i32,true)?;
                    self.fd(pid,peek(pid,a[2])? as i32,false)?;
                } else if !matches!(a[1],0x541b | 0x5450 | 0x5451) {
                    let link = self.fd_link(pid,a[0] as i32)?;
                    if link.is_absolute() && !((0..3).contains(&(a[0] as i32)) && self.stdio[a[0] as usize].as_ref() == Some(&link)) {
                        return Ok(Some(libc::ENOTTY)); // fail closed, permit ordinary ioctl fallbacks
                    }
                }
            }
            25 => { // leases and notification ioctls/fcntls are not normal data I/O.
                if matches!(a[1],1024 | 1026) { self.fd(pid,a[0] as i32,true)?; }
            }
            220 => ensure!(a[0] & (0x00800000u64 | 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000) == 0,"untraced or namespace clone is unsupported"),
            // Alternate asynchronous I/O, filesystem handles/mount APIs, external
            // FD/memory access and privileged device creation are not covered.
            0..=4 | 18 | 33 | 39..=42 | 51 | 60 | 89 | 97 | 104..=106 | 117
            | 224..=225 | 241 | 262..=265 | 268 | 270..=273 | 277 | 280 | 282 | 294
            | 428..=433 | 438 | 440 | 442..=446 | 448 => bail!("unsupported filesystem-capable syscall {nr}"),
            // Known harmless modern syscalls; unknown new syscall interfaces fail
            // closed as ENOSYS instead of silently acquiring new FS pathways.
            424 | 434 | 436 | 441 | 449 | 450 | 453..=456 | 462 => {},
            295..=u64::MAX => return Ok(Some(libc::ENOSYS)),
            _ => {},
        }
        Ok(None)
    }
}

struct Probe { writes: usize, checked_nr: bool, checked_memory: bool }
impl Probe {
    fn syscall(&mut self, pid: Pid, regs: &mut Registers) -> Result<Option<i32>> {
        match regs.x[8] {
            172 => {
                let mut nr = 0i32;
                regset(GETREGSET,pid,NT_ARM_SYSTEM_CALL,&mut nr)?;
                ensure!(nr == 172,"NT_ARM_SYSTEM_CALL does not report syscall entry");
                regset(SETREGSET,pid,NT_PRSTATUS,regs)?;
                let mut readback = Registers::default();
                regset(GETREGSET,pid,NT_PRSTATUS,&mut readback)?;
                ensure!(readback.x == regs.x && readback.pc == regs.pc,"register write/readback mismatch");
                self.checked_nr = true;
            }
            64 => {
                self.writes += 1;
                if self.writes == 1 {
                    let address = regs.x[1];
                    let original = peek(pid,address)?;
                    ensure!(original & 0xff == b'A' as u64,"cannot read child memory");
                    let changed = (original & !0xff) | b'B' as u64;
                    ptrace(POKEDATA,pid,address as usize,changed as usize)?;
                    ensure!(peek(pid,address)? == changed,"cannot write child memory");
                    self.checked_memory = true;
                } else { return Ok(Some(libc::EACCES)); }
            }
            _ => {},
        }
        Ok(None)
    }
}

enum Mode<'a> { Command(Guard<'a>), Check(Probe) }

fn trace(owned: &mut OwnedTracees, mode: &mut Mode<'_>, cancellation: Option<&WindowsSandboxCancellationToken>, timeout: Option<Duration>) -> Result<(i32,bool)> {
    let start = Instant::now();
    let mut tasks = HashMap::from([(owned.root,Task::default())]);
    let mut root_exit = None;
    let mut timed_out = false;
    let mut terminating = false;
    let mut regs = Registers::default();
    ptrace(SYSCALL,owned.root,0,0)?;
    while !owned.live.is_empty() {
        if !terminating && (CANCELLED.load(Ordering::Relaxed) || cancellation.is_some_and(|token| token.is_cancelled()) || timeout.is_some_and(|limit| start.elapsed() >= limit)) {
            timed_out = timeout.is_some_and(|limit| start.elapsed() >= limit);
            terminating = true;
            owned.kill();
        }
        let mut status = 0;
        // CLI has signal-driven cancellation; embedding callers may have a
        // callback/deadline, in which case poll without blocking the callback.
        let poll = cancellation.is_some() || timeout.is_some();
        let pid = unsafe { libc::waitpid(-1,&mut status,WALL | if poll { libc::WNOHANG } else { 0 }) };
        if pid == 0 { std::thread::sleep(Duration::from_millis(2)); continue; }
        if pid < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) { continue; }
            return Err(error).context("waitpid while tracing owned descendants");
        }
        if !owned.live.contains(&pid) {
            ensure!(libc::WIFSTOPPED(status),"unexpected non-owned terminal waitpid result {pid}");
            owned.adopt_newborn(pid)?;
            tasks.entry(pid).or_insert_with(|| Task { newborn:true, ..Task::default() });
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
            owned.live.remove(&pid);
            tasks.remove(&pid);
            if pid == owned.root {
                root_exit = Some(code);
                // A shell's background jobs must not survive its terminal state.
                terminating = true;
                owned.kill();
            }
            continue;
        }
        ensure!(libc::WIFSTOPPED(status),"unexpected wait status {status:#x}");
        let signal = libc::WSTOPSIG(status);
        let event = (status as u32) >> 16;
        if event != 0 {
            match event {
                1..=3 => {
                    let mut child: libc::c_ulong = 0;
                    ptrace(GETEVENTMSG,pid,0,(&mut child as *mut libc::c_ulong) as usize)?;
                    let child = i32::try_from(child).context("invalid fork event child PID")?;
                    ensure!(child > 0,"invalid fork event child PID");
                    owned.live.insert(child);
                    tasks.entry(child).or_insert_with(|| Task { newborn:true, ..Task::default() });
                    if terminating { unsafe { libc::kill(child,libc::SIGKILL); } }
                }
                4 => { // Non-leader thread exec changes TID to the leader PID.
                    let mut former: libc::c_ulong = 0;
                    ptrace(GETEVENTMSG,pid,0,(&mut former as *mut libc::c_ulong) as usize)?;
                    let former = former as Pid;
                    if former != pid {
                        if let Some(task) = tasks.remove(&former) { tasks.insert(pid,task); }
                        owned.live.remove(&former);
                    }
                    // Keep at_exit=true: exec event has a matching syscall exit.
                }
                6 => {}, // EXIT event is followed by the actual terminal wait.
                _ => bail!("unsupported ptrace lifecycle event {event}"),
            }
            ptrace(SYSCALL,pid,0,if terminating { libc::SIGKILL as usize } else { 0 })?;
            continue;
        }
        if terminating { ptrace(SYSCALL,pid,0,libc::SIGKILL as usize)?; continue; }
        let task = tasks.get_mut(&pid).context("missing tracee syscall phase")?;
        if task.newborn && signal == libc::SIGSTOP {
            task.newborn = false;
            ptrace(SETOPTIONS,pid,0,OPTIONS)?;
            ptrace(SYSCALL,pid,0,0)?;
            continue;
        }
        if signal == (libc::SIGTRAP | 0x80) {
            if task.phase.next_is_entry() {
                regset(GETREGSET,pid,NT_PRSTATUS,&mut regs)?;
                let errno = match mode {
                    Mode::Command(guard) => match guard.syscall(pid,regs.x[8],&regs.x) {
                        Ok(errno) => {
                            if let Some(errno) = errno { eprintln!("YJ_OHOS_DIRECTORY_DENIED pid={pid} syscall={} unsupported pathway errno={errno}",regs.x[8]); }
                            errno
                        }
                        Err(error) => {
                            eprintln!("YJ_OHOS_DIRECTORY_DENIED pid={pid} syscall={} {error:#}",regs.x[8]);
                            Some(libc::EACCES)
                        }
                    },
                    Mode::Check(probe) => probe.syscall(pid,&mut regs)?,
                };
                if let Some(errno) = errno {
                    skip(pid,&mut regs)?;
                    task.phase.denied_errno = Some(errno);
                }
            } else if let Some(errno) = task.phase.denied_errno.take() {
                regset(GETREGSET,pid,NT_PRSTATUS,&mut regs)?;
                regs.x[0] = (-i64::from(errno)) as u64;
                regset(SETREGSET,pid,NT_PRSTATUS,&mut regs)?;
            }
            ptrace(SYSCALL,pid,0,0)?;
        } else {
            // Forward real signals; don't turn SIGSEGV/SIGINT into successful runs.
            // A group stop has no syscall phase transition.
            ptrace(SYSCALL,pid,0,if signal == libc::SIGSTOP { 0 } else { signal as usize })?;
        }
    }
    Ok((root_exit.context("root tracee never reached a terminal state")?,timed_out))
}

fn inherited_fds() -> Result<Vec<RawFd>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").context("cannot enumerate inherited descriptors")? {
        if let Ok(fd) = entry?.file_name().to_string_lossy().parse::<i32>() { if fd > 2 { out.push(fd); } }
    }
    Ok(out)
}

unsafe fn child_traceme(parent: Pid, close_fds: &[RawFd], cwd: Option<&CString>) {
    unsafe {
        if libc::setpgid(0,0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL,0,0,0) != 0 || libc::getppid() != parent { libc::_exit(125); }
        for fd in close_fds { libc::close(*fd); }
        if let Some(cwd) = cwd { if libc::chdir(cwd.as_ptr()) != 0 { libc::_exit(125); } }
        // Only async-signal-safe raw operations occur after fork and before exec.
        if c_ptrace(TRACEME,0,0usize,0usize) != 0 { libc::_exit(125); }
        if libc::raise(libc::SIGSTOP) != 0 { libc::_exit(125); }
    }
}

/// Probe a disposable owned child, including actual remote memory mutation,
/// GET/SETREGSET of both ARM64 notes, syscall execution and skipped side effects.
pub fn ohos_check() -> Result<serde_json::Value> {
    let _signals = SignalHandlers::install()?;
    let (mut reader,writer) = pipe()?;
    let fd = writer.as_raw_fd();
    let parent = unsafe { libc::getpid() };
    let close_fds: Vec<_> = inherited_fds()?.into_iter().filter(|other| *other != fd).collect();
    let pid = unsafe { libc::fork() };
    ensure!(pid >= 0,"cannot fork capability child: {}",std::io::Error::last_os_error());
    if pid == 0 {
        unsafe {
            child_traceme(parent,&close_fds,None);
            if libc::syscall(172) <= 0 { libc::_exit(1); }
            let mut bytes = [b'A';8];
            if libc::syscall(64,fd,bytes.as_mut_ptr(),1usize) != 1 || bytes[0] != b'B' { libc::_exit(2); }
            if libc::syscall(64,fd,bytes.as_ptr(),1usize) != -1 || *libc::__errno_location() != libc::EACCES { libc::_exit(3); }
            libc::_exit(0);
        }
    }
    drop(writer);
    let mut owned = OwnedTracees::new(pid);
    initial_stop(pid)?;
    let mut mode = Mode::Check(Probe { writes:0, checked_nr:false, checked_memory:false });
    let (code,_) = trace(&mut owned,&mut mode,None,Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let Mode::Check(probe) = mode else { unreachable!() };
    ensure!(code == 0 && probe.checked_nr && probe.checked_memory && probe.writes == 2 && bytes == b"B", "OHOS ptrace read/write/skip capability probe failed (child exit {code})");
    Ok(serde_json::json!({"available":true,"backend":"ohos-ptrace","protection":"accidental-file-access","protocol":1}))
}

pub fn run_ohos_directory_control(raw: &str, readable: &[PathBuf], command: Vec<String>) -> Result<i32> {
    let policy = OhosDirectoryPolicy::from_state(raw,readable)?;
    ohos_check().context("OHOS ptrace startup capability check failed")?;
    let _signals = SignalHandlers::install()?;
    let result = run(&policy,command,std::env::vars().collect(),None,None,true)?;
    Ok(result.exit_code)
}

fn pipe() -> Result<(std::fs::File,std::fs::File)> {
    let mut fds = [-1;2];
    ensure!(unsafe { libc::pipe2(fds.as_mut_ptr(),libc::O_CLOEXEC) } == 0,"cannot create output pipe: {}",std::io::Error::last_os_error());
    Ok(unsafe { (std::fs::File::from_raw_fd(fds[0]),std::fs::File::from_raw_fd(fds[1])) })
}

fn output_reader(mut file: std::fs::File) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut collected = Vec::new();
        file.read_to_end(&mut collected)?;
        Ok(collected)
    })
}

fn run(policy: &OhosDirectoryPolicy, command: Vec<String>, env: HashMap<String,String>, timeout_ms: Option<u64>, cancellation: Option<WindowsSandboxCancellationToken>, stream: bool) -> Result<CaptureResult> {
    ensure!(!command.is_empty() && Path::new(&command[0]).is_absolute(),"OHOS requires an absolute command executable");
    let argv: Vec<CString> = command.iter().map(|arg| CString::new(arg.as_bytes())).collect::<std::result::Result<_,_>>()?;
    let env: Vec<CString> = env.iter().map(|(key,value)| CString::new(format!("{key}={value}"))).collect::<std::result::Result<_,_>>()?;
    let mut argv_ptrs: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect(); argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<_> = env.iter().map(|arg| arg.as_ptr()).collect(); env_ptrs.push(std::ptr::null());
    let cwd = CString::new(policy.cwd.as_os_str().as_bytes())?;
    // CLI streams directly through inherited stdout/stderr: no buffering or
    // extra output copies. File ownership also closes pipes on every error path.
    let pipes = if stream { None } else { Some([pipe()?,pipe()?]) };
    let close_fds = inherited_fds()?;
    let parent = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    ensure!(pid >= 0,"cannot fork command: {}",std::io::Error::last_os_error());
    if pid == 0 {
        unsafe {
            if let Some(pipes) = &pipes {
                if libc::dup2(pipes[0].1.as_raw_fd(),1) < 0 || libc::dup2(pipes[1].1.as_raw_fd(),2) < 0 { libc::_exit(125); }
            }
            child_traceme(parent,&close_fds,Some(&cwd));
            libc::execve(argv[0].as_ptr(),argv_ptrs.as_ptr(),env_ptrs.as_ptr());
            let message = b"yj-sandbox-run: cannot exec command\n";
            libc::write(2,message.as_ptr().cast(),message.len());
            libc::_exit(127);
        }
    }
    let mut owned = OwnedTracees::new(pid);
    let readers = pipes.map(|[(stdout,stdout_writer),(stderr,stderr_writer)]| {
        drop(stdout_writer);
        drop(stderr_writer);
        [output_reader(stdout),output_reader(stderr)]
    });
    let result = (|| {
        initial_stop(pid)?;
        let mut mode = Mode::Command(Guard::new(policy,pid));
        trace(&mut owned,&mut mode,cancellation.as_ref(),timeout_ms.map(Duration::from_millis))
    })();
    // Kill/reap before joining readers on every error; otherwise an inherited
    // descendant pipe can keep a reader blocked after an internal tracer failure.
    drop(owned);
    let mut output = [Vec::new(),Vec::new()];
    if let Some(readers) = readers {
        for (index,reader) in readers.into_iter().enumerate() {
            output[index] = reader.join().map_err(|_| anyhow::anyhow!("capture reader panicked"))??;
        }
    }
    let (exit_code,timed_out) = result?;
    let [stdout,stderr] = output;
    Ok(CaptureResult { exit_code,stdout,stderr,timed_out })
}

#[allow(clippy::too_many_arguments)]
pub fn run_sandbox_capture(permissions: &ResolvedWindowsSandboxPermissions, _state_dir: &Path, command: Vec<String>, cwd: &Path, env: HashMap<String,String>, timeout_ms: Option<u64>, cancellation: Option<WindowsSandboxCancellationToken>, use_private_desktop: bool, stream_output: bool) -> Result<CaptureResult> {
    ensure!(!permissions.has_full_disk_read_access() && !permissions.include_platform_defaults(),"OHOS requires explicit runtime read roots; full-disk/platform-default profiles are unsupported");
    ensure!(!permissions.should_apply_network_block(),"OHOS directory control does not implement network isolation");
    ensure!(!use_private_desktop,"private desktop is not supported on OHOS");
    let mut policy = OhosDirectoryPolicy::empty(std::fs::canonicalize(cwd)?);
    for root in permissions.readable_roots_for_cwd(cwd) { policy.add(root,Access::Read)?; }
    for root in permissions.writable_roots_for_cwd(cwd,&env) {
        policy.add(root.root,Access::Write)?;
        for path in root.read_only_subpaths { policy.add(path,Access::Read)?; }
    }
    ensure!(policy.allows(&policy.cwd,&policy.cwd,false),"cwd is not readable under the supplied policy");
    ohos_check().context("OHOS ptrace startup capability check failed")?;
    let _signals = SignalHandlers::install()?;
    run(&policy,command,env,timeout_ms,cancellation,stream_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathname_reads_preserve_nul_page_and_path_max_boundaries() {
        struct Mapping { base: *mut libc::c_void, length: usize }
        impl Drop for Mapping {
            fn drop(&mut self) { unsafe { libc::munmap(self.base,self.length); } }
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page_size >= PATH_MAX as libc::c_long);
        let page_size = page_size as usize;
        let length = 6 * page_size;
        let base = unsafe { libc::mmap(std::ptr::null_mut(),length,libc::PROT_READ | libc::PROT_WRITE,libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,-1,0) };
        assert_ne!(base,libc::MAP_FAILED);
        let mapping = Mapping { base,length };
        let bytes = unsafe { std::slice::from_raw_parts_mut(base.cast::<u8>(),length) };
        bytes[1..5].copy_from_slice(b"/\xffx\0");
        bytes[5*page_size-3..5*page_size].copy_from_slice(b"/x\0");
        bytes[page_size..page_size+PATH_MAX].fill(b'x');
        bytes[page_size+PATH_MAX-1] = 0;
        bytes[2*page_size..3*page_size].fill(b'x');
        bytes[3*page_size-3..3*page_size].copy_from_slice(b"/ab");
        bytes[3*page_size..3*page_size+8].copy_from_slice(b"/hidden\0");
        assert_eq!(unsafe { libc::mprotect(base.cast::<u8>().add(3*page_size).cast(),page_size,libc::PROT_NONE) },0);
        assert_eq!(unsafe { libc::mprotect(base.cast::<u8>().add(5*page_size).cast(),page_size,libc::PROT_NONE) },0);
        let parent = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                child_traceme(parent,&[],None);
                libc::_exit(0);
            }
        }
        let owned = OwnedTracees::new(pid);
        initial_stop(pid).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let policy = OhosDirectoryPolicy::empty(temp.path().to_owned());
        let mut guard = Guard::new(&policy,pid);
        let address = base as u64;
        let protected_readable = peek(pid,address+3*page_size as u64).is_ok();
        for bulk in [true,false] {
            guard.vm_page_size = if bulk { page_size } else { 0 };
            assert_eq!(guard.string(pid,address).unwrap().as_os_str().as_bytes(),b"");
            assert_eq!(guard.string(pid,address+1).unwrap().as_os_str().as_bytes(),b"/\xffx");
            assert_eq!(guard.string(pid,address+5*page_size as u64-3).unwrap(),PathBuf::from("/x"));
            assert_eq!(guard.string(pid,address+page_size as u64).unwrap().as_os_str().len(),PATH_MAX-1);
            assert!(guard.string(pid,address+2*page_size as u64).is_err());
            for (offset,expected) in [(3*page_size-3,"/ab/hidden"),(3*page_size,"/hidden")] {
                let result = guard.string(pid,address+offset as u64);
                if protected_readable {
                    assert_eq!(result.unwrap(),PathBuf::from(expected));
                } else {
                    assert!(result.is_err(),"protected pages must remain unreadable");
                }
            }
            // A previous successful read must not supply a stale NUL or pathname.
            for invalid in [0,1,u64::MAX] { assert!(guard.string(pid,invalid).is_err()); }
        }
        drop(owned);
        drop(mapping);
    }

    #[test]
    fn ancestor_metadata_fd_does_not_authorize_listing_or_data_operations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        std::fs::create_dir(&root).unwrap();
        let ancestor = std::fs::File::open(temp.path()).unwrap();
        let pid = unsafe { libc::getpid() };
        let mut policy = OhosDirectoryPolicy::empty(root.clone());
        policy.add(root,Access::Read).unwrap();
        let mut guard = Guard::new(&policy,pid);
        assert!(guard.checked_metadata(pid,temp.path(),true).is_ok());
        assert!(guard.checked_metadata(pid,Path::new("/"),true).is_ok());
        assert!(guard.checked_path(pid,temp.path(),false,true,false).is_err());
        let mut args = [0u64;31];
        args[0] = ancestor.as_raw_fd() as u64;
        assert!(guard.syscall(pid,80,&args).is_ok()); // fstat metadata only
        for nr in [61,63,64,46,52] {
            assert!(guard.syscall(pid,nr,&args).is_err(), "ancestor content syscall {nr}");
        }
        policy.add(temp.path().to_owned(),Access::Deny).unwrap();
        assert!(Guard::new(&policy,pid).checked_metadata(pid,temp.path(),true).is_err());
    }

    #[test]
    fn fd_operations_and_shared_mapping_cannot_promote_read_only_grants() {
        let temp = tempfile::tempdir().unwrap();
        let file = tempfile::tempfile_in(temp.path()).unwrap();
        let pid = unsafe { libc::getpid() };
        let mut ro = OhosDirectoryPolicy::empty(temp.path().to_owned());
        ro.add(temp.path().to_owned(),Access::Read).unwrap();
        let mut guard = Guard::new(&ro,pid);
        let mut args = [0u64;31];
        args[0] = file.as_raw_fd() as u64;
        for nr in [63,65,67,69,80,286] { assert!(guard.syscall(pid,nr,&args).is_ok(),"read syscall {nr}"); }
        for nr in [64,66,68,70,46,47,52,55,287] { assert!(guard.syscall(pid,nr,&args).is_err(),"write syscall {nr}"); }
        args[4] = file.as_raw_fd() as u64;
        args[3] = libc::MAP_PRIVATE as u64;
        assert!(guard.syscall(pid,222,&args).is_ok());
        args[3] = libc::MAP_SHARED as u64;
        assert!(guard.syscall(pid,222,&args).is_err()); // A writable FD could later gain shared writes.
        let read_fd = std::fs::File::open(format!("/proc/{pid}/fd/{}",file.as_raw_fd())).unwrap();
        args[4] = read_fd.as_raw_fd() as u64;
        args[2] = libc::PROT_READ as u64;
        assert!(guard.syscall(pid,222,&args).is_ok());
        args[2] |= libc::PROT_WRITE as u64;
        assert!(guard.syscall(pid,222,&args).is_err());
        args[4] = file.as_raw_fd() as u64;
        args[2] = libc::PROT_READ as u64;
        let mut rw = OhosDirectoryPolicy::empty(temp.path().to_owned());
        rw.add(temp.path().to_owned(),Access::Write).unwrap();
        assert!(Guard::new(&rw,pid).syscall(pid,222,&args).is_ok());
    }

    #[test]
    fn ordinary_threads_are_traced_and_async_filesystem_bypasses_use_fallback_errno() {
        let temp = tempfile::tempdir().unwrap();
        let policy = OhosDirectoryPolicy::empty(temp.path().to_owned());
        let pid = unsafe { libc::getpid() };
        let mut guard = Guard::new(&policy,pid);
        let mut args = [0u64;31];
        args[0] = 0x100 | 0x200 | 0x400 | 0x800 | 0x10000; // VM, FS, FILES, SIGHAND, THREAD
        assert!(guard.syscall(pid,220,&args).is_ok());
        args[0] |= 0x800000; // CLONE_UNTRACED must not escape lifecycle ownership.
        assert!(guard.syscall(pid,220,&args).is_err());
        for nr in [425,426,427,435,999] { assert_eq!(guard.syscall(pid,nr,&args).unwrap(),Some(libc::ENOSYS)); }
        for nr in [0,2,33,40,117,265,270,271,438] { assert!(guard.syscall(pid,nr,&args).is_err()); }
        assert_eq!(guard.syscall(pid,98,&args).unwrap(),None); // ordinary futex
    }

    #[test]
    fn implicit_shebang_interpreter_must_have_its_own_read_grant() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let interpreter = temp.path().join("interpreter");
        let script = work.join("script");
        std::fs::write(&interpreter,b"ordinary text").unwrap();
        std::fs::write(&script,format!("#!{}\n",interpreter.display())).unwrap();
        let mut policy = OhosDirectoryPolicy::empty(work.clone());
        policy.add(work,Access::Read).unwrap();
        let pid = unsafe { libc::getpid() };
        assert!(Guard::new(&policy,pid).exec_image(pid,&script,0).is_err());
        policy.add(interpreter,Access::Read).unwrap();
        assert!(Guard::new(&policy,pid).exec_image(pid,&script,0).is_ok());
    }

    #[test]
    fn capability_protocol_is_backed_by_real_owned_child_read_write_and_skip() {
        assert_eq!(ohos_check().unwrap(),serde_json::json!({
            "available":true,"backend":"ohos-ptrace","protection":"accidental-file-access","protocol":1
        }));
    }
}
