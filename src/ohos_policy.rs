//! Per-run path policy for the OHOS accidental-access guard (not an isolation boundary).
use anyhow::{Context, Result, bail, ensure};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access { Read, Write, Deny }

#[derive(Debug)]
struct Rule { lexical: PathBuf, resolved: PathBuf, access: Access }

#[derive(Debug)]
pub struct OhosDirectoryPolicy { pub(crate) cwd: PathBuf, rules: Vec<Rule> }

/// Lexical normalization is an additional policy check, never a replacement for
/// resolving symlinks before `..` in the kernel's pathname order.
pub(crate) fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => { out.pop(); }
            Component::CurDir => {}
            component => out.push(component.as_os_str()),
        }
    }
    out
}

/// Resolve existing ancestors of a creation path. Do not normalize away `..`
/// before canonicalization: a symlink followed by `..` changes its meaning.
pub(crate) fn resolve(path: &Path, follow_final: bool) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "path must be absolute: {}", path.display());
    if !follow_final {
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            return Ok(resolve(parent, true)?.join(name));
        }
    }
    match dunce::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().context("cannot resolve path root")?;
            let name = path.file_name().context("cannot resolve missing dot component")?;
            Ok(resolve(parent, true)?.join(name))
        }
        Err(error) => Err(error).with_context(|| format!("cannot resolve {}", path.display())),
    }
}

impl OhosDirectoryPolicy {
    pub fn from_state(raw: &str, additional_readable_roots: &[PathBuf]) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(raw).context("invalid sandbox state JSON")?;
        let cwd = PathBuf::from(value["sandboxCwd"].as_str().context("missing sandboxCwd")?);
        ensure!(cwd.is_absolute(), "sandboxCwd must be an absolute native path");
        let cwd = dunce::canonicalize(cwd).context("cannot resolve sandboxCwd")?;
        ensure!(cwd.is_dir(), "sandboxCwd must be a directory");
        let profile = &value["permissionProfile"];
        ensure!(profile["type"] == "managed", "OHOS requires a managed permission profile");
        ensure!(profile["network"] == "enabled", "OHOS directory control does not implement network isolation; network must be enabled");
        let fs = &profile["file_system"];
        ensure!(fs["type"] == "restricted", "OHOS requires explicit restricted filesystem roots");
        let entries = fs["entries"].as_array().context("missing restricted filesystem entries")?;
        let mut policy = Self { cwd, rules: Vec::with_capacity(entries.len() + additional_readable_roots.len()) };
        for entry in entries {
            ensure!(entry["path"]["type"] == "path", "OHOS requires explicit native path entries, not special or glob roots");
            let path = PathBuf::from(entry["path"]["path"].as_str().context("missing entry path")?);
            let access = match entry["access"].as_str() {
                Some("read") => Access::Read,
                Some("write") => Access::Write,
                Some("deny" | "none") => Access::Deny,
                _ => bail!("unsupported filesystem entry access"),
            };
            policy.add(path, access)?;
        }
        for path in additional_readable_roots { policy.add(path.clone(), Access::Read)?; }
        ensure!(policy.allows(&policy.cwd, &policy.cwd, false), "sandboxCwd is not readable under the supplied policy");
        Ok(policy)
    }

    pub(crate) fn empty(cwd: PathBuf) -> Self { Self { cwd, rules: Vec::new() } }

    pub(crate) fn add(&mut self, path: PathBuf, access: Access) -> Result<()> {
        ensure!(path.is_absolute(), "policy root must be absolute: {}", path.display());
        ensure!(access == Access::Read || path.parent().is_some(), "whole-filesystem roots must be read-only on OHOS");
        // These are tracee-relative magic links, not the tracer's own /proc PID.
        let resolved = if path.starts_with("/proc/self") || path.starts_with("/proc/thread-self") {
            lexical(&path)
        } else {
            resolve(&path, true)?
        };
        ensure!(access == Access::Read || resolved.parent().is_some(), "policy root resolves to the whole filesystem and must be read-only");
        self.rules.push(Rule { lexical: lexical(&path), resolved, access });
        Ok(())
    }

    fn access(&self, path: &Path, resolved: bool) -> Option<Access> {
        let mut best: Option<(usize, Access)> = None;
        for rule in &self.rules {
            let root = if resolved {
                &rule.resolved
            } else if path.starts_with(&rule.lexical) {
                &rule.lexical
            } else {
                // Relative cwd/dirfd operations expose the canonical root, even
                // when the caller originally granted a symlink spelling.
                &rule.resolved
            };
            if !path.starts_with(root) { continue; }
            if rule.access == Access::Deny { return Some(Access::Deny); }
            let depth = root.components().count();
            if best.is_none_or(|(old_depth, old_access)| depth > old_depth || (depth == old_depth && old_access == Access::Write && rule.access == Access::Read)) {
                best = Some((depth, rule.access));
            }
        }
        best.map(|(_, access)| access)
    }

    pub(crate) fn allows(&self, path: &Path, resolved: &Path, write: bool) -> bool {
        let permitted = |access| matches!(access, Some(Access::Write)) || (!write && matches!(access, Some(Access::Read)));
        permitted(self.access(&lexical(path), false)) && permitted(self.access(resolved, true))
    }

    /// Ancestors are visible only to metadata queries, never to content I/O.
    /// Check both spellings independently so symlinks cannot turn a grant into
    /// metadata access to unrelated paths, and explicit denials still dominate.
    pub(crate) fn allows_metadata(&self, path: &Path, resolved: &Path) -> bool {
        let path = lexical(path);
        let permitted = |path: &Path, resolved: bool| {
            match self.access(path, resolved) {
                Some(Access::Deny) => return false,
                Some(Access::Read | Access::Write) => return true,
                None => {}
            }
            self.rules.iter().any(|rule| rule.access != Access::Deny &&
                (rule.resolved.starts_with(path) || rule.lexical.starts_with(path)))
        };
        permitted(&path, false) && permitted(resolved, true)
    }

    /// Moving/removing an ancestor must not move a protected subtree out of its
    /// policy root, even when that ancestor itself is writable.
    pub(crate) fn protects_descendant(&self, path: &Path, resolved: &Path) -> bool {
        let path = lexical(path);
        self.rules.iter().any(|rule| rule.access != Access::Write &&
            (rule.lexical.starts_with(&path) || rule.resolved.starts_with(resolved)))
    }
}

/// Pure stop-phase state; fork children start at entry, exec retains its exit.
#[derive(Debug, Default)]
pub(crate) struct SyscallPhase { pub(crate) at_exit: bool, pub(crate) denied_errno: Option<i32> }
impl SyscallPhase {
    pub(crate) fn next_is_entry(&mut self) -> bool {
        let entry = !self.at_exit;
        self.at_exit = !self.at_exit;
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(entries: &[(&Path, &str)], cwd: &Path) -> OhosDirectoryPolicy {
        let entries: Vec<_> = entries.iter().map(|(path, access)| serde_json::json!({"path":{"type":"path","path":path},"access":access})).collect();
        OhosDirectoryPolicy::from_state(&serde_json::json!({"sandboxCwd":cwd,"permissionProfile":{"type":"managed","network":"enabled","file_system":{"type":"restricted","entries":entries}}}).to_string(), &[]).unwrap()
    }
    #[test]
    fn filesystem_root_read_allows_outside_content_but_not_outside_writes() {
        let temp = tempfile::tempdir().unwrap();
        let base = dunce::canonicalize(temp.path()).unwrap();
        let root = base.ancestors().last().unwrap();
        let work = base.join("work");
        let outside = base.join("outside.txt");
        let protected = work.join("reference");
        let denied = base.join("denied");
        let denied_child = denied.join("nested");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::create_dir_all(&denied_child).unwrap();
        std::fs::write(&outside, "App-readable content").unwrap();
        let p = policy(&[(root,"read"),(&work,"write"),(&protected,"read"),
            (&protected,"write"),(&denied,"deny"),(&denied_child,"write")], &work);
        assert!(p.allows(&outside,&outside,false));
        assert!(!p.allows(&outside,&outside,true));
        assert!(p.allows(&work.join("new.txt"),&work.join("new.txt"),true));
        assert!(p.allows(&protected,&protected,false));
        assert!(!p.allows(&protected,&protected,true));
        assert!(!p.allows(&denied_child,&denied_child,false));
        assert!(!p.allows(&denied_child,&denied_child,true));
        assert!(!p.allows(root,root,true));
        assert!(p.protects_descendant(&work,&work));
        let mut rejected = OhosDirectoryPolicy::empty(work);
        assert!(rejected.add(root.to_owned(),Access::Write).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn root_read_preserves_resolved_escape_and_denial_checks() {
        let temp = tempfile::tempdir().unwrap();
        let base = dunce::canonicalize(temp.path()).unwrap();
        let root = base.ancestors().last().unwrap();
        let work = base.join("work");
        let outside = base.join("outside");
        let denied = base.join("denied");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&denied).unwrap();
        let outside_alias = work.join("outside-link");
        let denied_alias = work.join("denied-link");
        let root_alias = base.join("root-link");
        std::os::unix::fs::symlink(&outside,&outside_alias).unwrap();
        std::os::unix::fs::symlink(&denied,&denied_alias).unwrap();
        std::os::unix::fs::symlink(root,&root_alias).unwrap();
        let p = policy(&[(root,"read"),(&work,"write"),(&denied,"deny")], &work);
        assert!(p.allows(&outside_alias,&outside,false));
        assert!(!p.allows(&outside_alias,&outside,true));
        assert!(!p.allows(&denied_alias,&denied,false));
        assert!(!p.allows(&denied_alias,&denied,true));
        let mut rejected = OhosDirectoryPolicy::empty(work);
        assert!(rejected.add(root_alias,Access::Write).is_err());
    }

    #[test]
    fn consumer_state_read_only_ties_and_children_override_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let child = root.join("readonly");
        std::fs::create_dir(&child).unwrap();
        let p = policy(&[(root,"write"),(&child,"read"),(&child,"write")], root);
        assert!(p.allows(root,root,true));
        assert!(p.allows(&child,&child,false));
        assert!(!p.allows(&child,&child,true));
        assert!(p.protects_descendant(root, root));
        assert!(!p.allows(&root.with_extension("sibling"), &root.with_extension("sibling"), false));
    }
    #[test]
    fn explicit_denial_cannot_be_overridden_by_deeper_write() {
        let temp = tempfile::tempdir().unwrap();
        let denied = temp.path().join("private");
        let nested = denied.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let p = policy(&[(temp.path(),"write"),(&denied,"deny"),(&nested,"write")],temp.path());
        assert!(!p.allows(&nested,&nested,false));
        assert!(!p.allows(&nested,&nested,true));
    }
    #[test]
    fn independent_runs_do_not_share_grants() {
        let temp = tempfile::tempdir().unwrap();
        let ro = policy(&[(temp.path(),"read")], temp.path());
        let rw = policy(&[(temp.path(),"write")], temp.path());
        assert!(!ro.allows(temp.path(),temp.path(),true));
        assert!(rw.allows(temp.path(),temp.path(),true));
        assert!(!ro.allows(temp.path(),temp.path(),true));
    }
    #[test]
    fn escape_is_not_a_prefix_or_lexical_dot_permission() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        std::fs::create_dir(&root).unwrap();
        let p = policy(&[(&root,"write")], &root);
        let escape = root.join("../outside");
        assert!(!p.allows(&escape,&resolve(&escape,true).unwrap(),true));
        assert!(!p.allows(&root.with_file_name("work-sibling"), &root.with_file_name("work-sibling"),true));
    }
    #[test]
    fn granted_ancestors_have_metadata_but_no_content_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("work");
        std::fs::create_dir(&root).unwrap();
        for access in ["read", "write"] {
            let p = policy(&[(&root,access)], &root);
            for ancestor in root.ancestors().skip(1) {
                assert!(p.allows_metadata(ancestor,ancestor), "metadata: {}", ancestor.display());
                assert!(!p.allows(ancestor,ancestor,false), "read/list: {}", ancestor.display());
                assert!(!p.allows(ancestor,ancestor,true), "write: {}", ancestor.display());
            }
            let outside = root.with_file_name("unrelated");
            assert!(!p.allows_metadata(&outside,&outside));
            assert!(p.allows_metadata(&root,&root));
            assert!(p.allows(&root,&root,false));
            assert_eq!(p.allows(&root,&root,true), access == "write");
        }
    }

    #[test]
    fn metadata_ancestor_grants_do_not_override_denials() {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let denied = root.join("denied");
        let nested = denied.join("nested");
        let cwd = root.join("cwd");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        let p = policy(&[(&cwd,"read"),(&denied,"deny"),(&nested,"write")], &cwd);
        assert!(!p.allows_metadata(&denied,&denied));
        assert!(!p.allows_metadata(&nested,&nested));
        assert!(!p.allows_metadata(&cwd,&denied));
        assert!(!p.allows_metadata(&denied,&cwd));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parent_order_and_alias_denials_are_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(outside.join("nested")).unwrap();
        std::os::unix::fs::symlink(outside.join("nested"),work.join("link")).unwrap();
        let p = policy(&[(&work,"write")], &work);
        let path = work.join("link/../new");
        assert_eq!(resolve(&path,true).unwrap(),outside.join("new"));
        assert!(!p.allows(&path,&resolve(&path,true).unwrap(),true));
    }
    #[cfg(unix)]
    #[test]
    fn canonical_cwd_and_fd_paths_keep_a_symlink_root_grant() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        let alias = temp.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real,&alias).unwrap();
        let p = policy(&[(&alias,"write")],&alias);
        assert_eq!(p.cwd,real);
        assert!(p.allows(&real,&real,true));
        assert!(p.allows(&alias,&real,true));
    }
    #[cfg(unix)]
    #[test]
    fn metadata_checks_both_lexical_and_resolved_ancestors() {
        let temp = tempfile::tempdir().unwrap();
        let base = dunce::canonicalize(temp.path()).unwrap();
        let real = base.join("physical/work");
        let aliases = base.join("logical");
        let alias = aliases.join("work");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir(&aliases).unwrap();
        std::os::unix::fs::symlink(&real,&alias).unwrap();
        let p = policy(&[(&alias,"read")], &alias);
        assert!(p.allows_metadata(&aliases,&aliases));
        assert!(p.allows_metadata(real.parent().unwrap(),real.parent().unwrap()));
        assert!(p.allows_metadata(&alias,&real));
        assert!(!p.allows(&aliases,&aliases,false));
        let unrelated = base.join("unrelated");
        assert!(!p.allows_metadata(&aliases,&unrelated));
        assert!(!p.allows_metadata(&unrelated,&aliases));
        let denied = policy(&[(&alias,"read"),(&aliases,"deny")], &real);
        assert!(!denied.allows_metadata(&aliases,&aliases));
    }

    #[test]
    fn explicit_runtime_scratch_write_is_more_specific_than_runtime_read() {
        let temp = tempfile::tempdir().unwrap();
        let scratch = temp.path().join("scratch");
        let protected = scratch.join("readonly");
        std::fs::create_dir_all(&protected).unwrap();
        let p = policy(&[(temp.path(),"read"),(&scratch,"write"),(&protected,"read")],temp.path());
        assert!(!p.allows(temp.path(),temp.path(),true));
        assert!(p.allows(&scratch,&scratch,true));
        assert!(!p.allows(&protected,&protected,true));
        assert!(p.allows(&protected,&protected,false));
    }
    #[test]
    fn state_rejects_ungranted_cwd_instead_of_inventing_a_grant() {
        let temp = tempfile::tempdir().unwrap();
        let allowed = temp.path().join("allowed");
        std::fs::create_dir(&allowed).unwrap();
        let state = serde_json::json!({"sandboxCwd":temp.path(),"permissionProfile":{
            "type":"managed","network":"enabled","file_system":{"type":"restricted","entries":[
                {"path":{"type":"path","path":allowed},"access":"write"}
            ]}
        }});
        assert!(OhosDirectoryPolicy::from_state(&state.to_string(),&[]).is_err());
    }
    #[test]
    fn child_entry_and_exec_exit_do_not_flip_the_wrong_stop() {
        let mut root = SyscallPhase::default();
        assert!(root.next_is_entry()); // exec entry
        // PTRACE_EVENT_EXEC is not a syscall stop.
        assert!(!root.next_is_entry()); // matching exec exit
        assert!(root.next_is_entry()); // clone entry
        let mut child = SyscallPhase::default();
        assert!(child.next_is_entry()); // set_tid_address, not clone exit
        assert!(!root.next_is_entry()); // parent clone exit
        child.denied_errno = Some(13);
        assert!(!child.next_is_entry());
        assert_eq!(child.denied_errno.take(),Some(13));
        assert!(child.next_is_entry());
    }
    #[test]
    fn rejects_implicit_roots_unrestricted_or_network_claims() {
        let temp = tempfile::tempdir().unwrap();
        for network in ["restricted","missing"] {
            let state=serde_json::json!({"sandboxCwd":temp.path(),"permissionProfile":{"type":"managed","network":network,"file_system":{"type":"restricted","entries":[]}}});
            assert!(OhosDirectoryPolicy::from_state(&state.to_string(),&[]).is_err());
        }
        let mut p = OhosDirectoryPolicy::empty(temp.path().to_owned());
        assert!(p.add(PathBuf::from(std::path::MAIN_SEPARATOR.to_string()),Access::Write).is_err());
    }
}
