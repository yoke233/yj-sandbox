//! Small local stand-in for Codex's `codex_utils_absolute_path::AbsolutePathBuf`.
//!
//! The macOS Seatbelt vendor code only needs a narrow subset of the upstream
//! helper. Keeping this type small lets `seatbelt.rs` stay close to Codex while
//! avoiding a dependency on the full Codex workspace.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AbsolutePathBuf(PathBuf);

impl AbsolutePathBuf {
    pub(crate) fn from_absolute_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(format!("path is not absolute: {}", path.display()));
        }
        Ok(Self(path.to_path_buf()))
    }

    pub(crate) fn resolve_path_against_base(path: impl AsRef<Path>, base: &Path) -> Self {
        let path = path.as_ref();
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        };
        Self(resolved)
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn into_path_buf(self) -> PathBuf {
        self.0
    }

    pub(crate) fn join(&self, path: impl AsRef<Path>) -> Self {
        Self(self.0.join(path))
    }

    pub(crate) fn to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        self.0.to_string_lossy()
    }
}

impl AsRef<Path> for AbsolutePathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl fmt::Display for AbsolutePathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl TryFrom<&Path> for AbsolutePathBuf {
    type Error = String;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::from_absolute_path(value)
    }
}

impl TryFrom<PathBuf> for AbsolutePathBuf {
    type Error = String;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::from_absolute_path(value)
    }
}

impl TryFrom<&str> for AbsolutePathBuf {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_absolute_path(Path::new(value))
    }
}

impl From<AbsolutePathBuf> for PathBuf {
    fn from(value: AbsolutePathBuf) -> Self {
        value.0
    }
}

impl PartialEq<OsStr> for AbsolutePathBuf {
    fn eq(&self, other: &OsStr) -> bool {
        self.0.as_os_str() == other
    }
}
