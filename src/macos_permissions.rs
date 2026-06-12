//! Local permission model consumed by the vendored macOS Seatbelt generator.
//!
//! Codex builds these values from `PermissionProfile` / `FileSystemSandboxPolicy`.
//! This crate keeps a smaller self-contained model that still exposes the
//! accessor shape used by `codex-rs/sandboxing/src/seatbelt.rs`.

use crate::absolute_path::AbsolutePathBuf;
use std::path::Path;

pub(crate) const PROTECTED_METADATA_PATH_NAMES: &[&str] = &[".git", ".agents", ".codex"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NetworkSandboxPolicy {
    #[default]
    Restricted,
    Enabled,
}

impl NetworkSandboxPolicy {
    pub(crate) fn is_enabled(self) -> bool {
        matches!(self, NetworkSandboxPolicy::Enabled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WritableRoot {
    pub(crate) root: AbsolutePathBuf,
    pub(crate) read_only_subpaths: Vec<AbsolutePathBuf>,
    pub(crate) protected_metadata_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileSystemSandboxPolicy {
    full_disk_read: bool,
    full_disk_write: bool,
    include_platform_defaults: bool,
    readable_roots: Vec<AbsolutePathBuf>,
    writable_roots: Vec<WritableRoot>,
    unreadable_roots: Vec<AbsolutePathBuf>,
    unreadable_globs: Vec<String>,
}

impl FileSystemSandboxPolicy {
    pub(crate) fn read_only_full_disk() -> Self {
        Self {
            full_disk_read: true,
            full_disk_write: false,
            include_platform_defaults: false,
            readable_roots: Vec::new(),
            writable_roots: Vec::new(),
            unreadable_roots: Vec::new(),
            unreadable_globs: Vec::new(),
        }
    }

    pub(crate) fn workspace_write_full_read(writable_roots: Vec<WritableRoot>) -> Self {
        Self {
            full_disk_read: true,
            full_disk_write: false,
            include_platform_defaults: false,
            readable_roots: Vec::new(),
            writable_roots,
            unreadable_roots: Vec::new(),
            unreadable_globs: Vec::new(),
        }
    }

    pub(crate) fn has_full_disk_read_access(&self) -> bool {
        self.full_disk_read
    }

    pub(crate) fn has_full_disk_write_access(&self) -> bool {
        self.full_disk_write
    }

    pub(crate) fn include_platform_defaults(&self) -> bool {
        self.include_platform_defaults
    }

    pub(crate) fn get_readable_roots_with_cwd(&self, _cwd: &Path) -> Vec<AbsolutePathBuf> {
        self.readable_roots.clone()
    }

    pub(crate) fn get_writable_roots_with_cwd(&self, _cwd: &Path) -> Vec<WritableRoot> {
        self.writable_roots.clone()
    }

    pub(crate) fn get_unreadable_roots_with_cwd(&self, _cwd: &Path) -> Vec<AbsolutePathBuf> {
        self.unreadable_roots.clone()
    }

    pub(crate) fn get_unreadable_globs_with_cwd(&self, _cwd: &Path) -> Vec<String> {
        self.unreadable_globs.clone()
    }

    pub(crate) fn can_write_path_with_cwd(&self, path: &Path, cwd: &Path) -> bool {
        if self.full_disk_write {
            return !self.is_unreadable(path, cwd);
        }
        self.writable_roots.iter().any(|root| {
            path.starts_with(root.root.as_path())
                && !root
                    .read_only_subpaths
                    .iter()
                    .any(|excluded| path == excluded.as_path() || path.starts_with(excluded.as_path()))
        })
    }

    fn is_unreadable(&self, path: &Path, _cwd: &Path) -> bool {
        self.unreadable_roots
            .iter()
            .any(|root| path == root.as_path() || path.starts_with(root.as_path()))
    }
}
