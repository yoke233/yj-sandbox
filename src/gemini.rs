// Ported from Google Gemini CLI's GeminiSandbox.cs at
// ac42fb0a24fe7349e9968e2359ef5232f1cb6e72.
// Copyright 2026 Google LLC. SPDX-License-Identifier: Apache-2.0.

use crate::acl::ensure_allow_write_aces;
use crate::path_normalization::canonical_path_key;
use crate::path_normalization::canonicalize_path;
use crate::token::LocalSid;
use crate::token::get_current_token_for_restriction;
use crate::winutil::to_wide;
use anyhow::Result;
use anyhow::anyhow;
use std::ffi::c_void;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::CreateRestrictedToken;
use windows_sys::Win32::Security::GetSecurityDescriptorSacl;
use windows_sys::Win32::Security::LABEL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::Security::SetTokenInformation;
use windows_sys::Win32::Security::TOKEN_MANDATORY_LABEL;
use windows_sys::Win32::Security::TokenIntegrityLevel;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;

const DISABLE_MAX_PRIVILEGE: u32 = 0x0000_0001;
const LOW_INTEGRITY_SID: &str = "S-1-16-4096";
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
const SE_FILE_OBJECT: i32 = 1;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

struct WritableRoot {
    path: PathBuf,
    key: String,
    propagate: bool,
}

fn canonical_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn is_descendant_key(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    let prefix = if parent.ends_with('/') {
        parent.to_string()
    } else {
        format!("{parent}/")
    };
    child.starts_with(&prefix)
}

/// Creates the current-user token used by Gemini's Windows sandbox: privileges
/// are removed without LUA_TOKEN, WRITE_RESTRICTED, or restricting SIDs, then
/// the token's mandatory integrity level is lowered to Low.
unsafe fn create_low_integrity_token() -> Result<(HANDLE, LocalSid)> {
    let base_token = get_current_token_for_restriction()?;
    let mut low_token: HANDLE = 0;
    let created = CreateRestrictedToken(
        base_token,
        DISABLE_MAX_PRIVILEGE,
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        &mut low_token,
    );
    let create_error = if created == 0 {
        Some(GetLastError())
    } else {
        None
    };
    CloseHandle(base_token);
    if let Some(error) = create_error {
        return Err(anyhow!("CreateRestrictedToken failed: {error}"));
    }

    let low_sid = match LocalSid::from_string(LOW_INTEGRITY_SID) {
        Ok(sid) => sid,
        Err(error) => {
            CloseHandle(low_token);
            return Err(error);
        }
    };
    let mut label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low_sid.as_ptr(),
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    if SetTokenInformation(
        low_token,
        TokenIntegrityLevel,
        &mut label as *mut _ as *mut c_void,
        std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
    ) == 0
    {
        let error = GetLastError();
        CloseHandle(low_token);
        return Err(anyhow!(
            "SetTokenInformation(TokenIntegrityLevel) failed: {error}"
        ));
    }

    Ok((low_token, low_sid))
}

unsafe fn set_low_integrity_label(path: &Path, propagate_to_existing_children: bool) -> Result<()> {
    let sddl = if path.is_dir() {
        "S:(ML;OICI;NW;;;LW)"
    } else {
        "S:(ML;;NW;;;LW)"
    };
    let mut security_descriptor: *mut c_void = std::ptr::null_mut();
    let mut security_descriptor_size = 0u32;
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(
        to_wide(sddl).as_ptr(),
        1,
        &mut security_descriptor,
        &mut security_descriptor_size,
    ) == 0
    {
        return Err(anyhow!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            GetLastError()
        ));
    }

    let result = (|| {
        let mut sacl_present = 0;
        let mut sacl_defaulted = 0;
        let mut sacl: *mut ACL = std::ptr::null_mut();
        if GetSecurityDescriptorSacl(
            security_descriptor,
            &mut sacl_present,
            &mut sacl,
            &mut sacl_defaulted,
        ) == 0
        {
            return Err(anyhow!(
                "GetSecurityDescriptorSacl failed: {}",
                GetLastError()
            ));
        }
        if sacl_present == 0 || sacl.is_null() {
            return Err(anyhow!("low-integrity security descriptor has no SACL"));
        }

        let code = if propagate_to_existing_children {
            SetNamedSecurityInfoW(
                to_wide(path).as_ptr(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sacl,
            )
        } else {
            // MAXIMUM_ALLOWED prevents SetSecurityInfo from propagating an
            // inheritable ACE through a potentially large existing TEMP tree.
            // New children still inherit the OI/CI Low label from the root.
            let handle = CreateFileW(
                to_wide(path).as_ptr(),
                MAXIMUM_ALLOWED,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                0,
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(anyhow!(
                    "CreateFileW for low-integrity label failed for {}: {}",
                    path.display(),
                    GetLastError()
                ));
            }
            let code = SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sacl,
            );
            CloseHandle(handle);
            code
        };
        if code != ERROR_SUCCESS {
            return Err(anyhow!(
                "setting low-integrity label failed for {}: {code}",
                path.display()
            ));
        }
        Ok(())
    })();

    LocalFree(security_descriptor as HLOCAL);
    result
}

/// Prepares Gemini-compatible write access for every resolved writable root
/// and returns the Low Integrity token used to spawn the child process.
pub(crate) fn prepare_gemini_security(
    writable_roots: impl IntoIterator<Item = PathBuf>,
    non_propagating_roots: &[PathBuf],
) -> Result<HANDLE> {
    let non_propagating_root_keys = non_propagating_roots
        .iter()
        .map(|root| canonical_path_key(root))
        .collect::<std::collections::HashSet<_>>();
    let mut candidates = writable_roots
        .into_iter()
        .map(|root| {
            let path = canonicalize_path(&root);
            let key = canonical_key(&path);
            let propagate = !non_propagating_root_keys.contains(&key);
            WritableRoot {
                path,
                key,
                propagate,
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        a.key
            .len()
            .cmp(&b.key.len())
            .then_with(|| a.key.cmp(&b.key))
    });
    let mut writable_roots: Vec<WritableRoot> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if writable_roots.iter().any(|existing| {
            existing.key == candidate.key
                || (existing.propagate
                    && candidate.propagate
                    && existing.path.is_dir()
                    && is_descendant_key(&existing.key, &candidate.key))
        }) {
            continue;
        }
        writable_roots.push(candidate);
    }

    let (low_token, low_sid) = unsafe { create_low_integrity_token()? };
    unsafe {
        for root in &writable_roots {
            if root.propagate
                && let Err(error) = ensure_allow_write_aces(&root.path, &[low_sid.as_ptr()])
            {
                eprintln!(
                    "warning: Gemini sandbox failed to apply Low write ACL to {}: {error:#}",
                    root.path.display()
                );
            }
            if let Err(error) = set_low_integrity_label(&root.path, root.propagate) {
                eprintln!(
                    "warning: Gemini sandbox failed to apply Low integrity label to {}: {error:#}",
                    root.path.display()
                );
            }
        }
    }
    Ok(low_token)
}
