//! Restricting who may read WinPerf's data (T35, NFR-003).
//!
//! The database holds a history of every program that ran and how much it used, so it should not
//! be readable by every user of the machine. [`restrict_to_admins_and_user`] gives a folder or file
//! a protected access list (no inheritance from the parent) that allows only SYSTEM, the
//! Administrators group and the account that is running the call, and passes the same list down
//! to what is inside. Everyone else, including the other standard users, loses access.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

/// Closes a handle when dropped.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed exactly once, here.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// The SID of the account running this process, as text (`S-1-5-21-...`). An elevated process
/// reports the same user as an unelevated one.
fn current_user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: current-process pseudo handle and a valid out-pointer.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(io::Error::other)?;
    let token = Token(token);
    let mut needed = 0u32;
    // SAFETY: a size query: null buffer, zero length, valid out-pointer.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::other("could not size the token user"));
    }
    // Aligned for the TOKEN_USER the call writes at the start of the buffer.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buffer` is writable and at least `needed` bytes, aligned for TOKEN_USER.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &mut needed,
        )
    }
    .map_err(io::Error::other)?;
    // SAFETY: the call above filled the buffer with a TOKEN_USER whose SID points into the buffer.
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut text = PWSTR::null();
    // SAFETY: a valid SID from the token and a valid out-pointer; the result is freed below.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(io::Error::other)?;
    // SAFETY: `text` is a NUL-terminated string allocated by the call above.
    let sid = unsafe { text.to_string() }.map_err(io::Error::other);
    // SAFETY: allocated with LocalAlloc by ConvertSidToStringSidW; freed once.
    unsafe { LocalFree(Some(HLOCAL(text.0.cast::<c_void>()))) };
    sid
}

/// The access list as SDDL: protected (`P`, nothing inherited from the parent), full control for
/// SYSTEM (`SY`), the Administrators group (`BA`) and `user_sid`, passed on to files (`OI`) and
/// folders (`CI`) below.
fn sddl_for(user_sid: &str) -> String {
    format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})")
}

/// Allow only SYSTEM, the Administrators group and the current account to use `path` (a folder or
/// a file), and everything inside it. Replaces whatever access list it had.
pub fn restrict_to_admins_and_user(path: &Path) -> io::Result<()> {
    let sddl: Vec<u16> = sddl_for(&current_user_sid()?)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated; `descriptor` is a valid out-pointer, freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io::Error::other)?;

    let result = (|| {
        let mut present = windows::core::BOOL::default();
        let mut defaulted = windows::core::BOOL::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: a descriptor from the call above and valid out-pointers.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            .map_err(io::Error::other)?;
        if !present.as_bool() || acl.is_null() {
            return Err(io::Error::other("the access list has no DACL"));
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `acl` points into `descriptor`,
        // which is still allocated.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(acl.cast_const()),
                None,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status.0 as i32))
        }
    })();
    // SAFETY: allocated with LocalAlloc by the conversion call; freed once.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn the_access_list_names_system_administrators_and_the_user_only() {
        let sddl = sddl_for("S-1-5-21-1-2-3-1001");
        assert!(sddl.starts_with("D:P"), "protected: {sddl}");
        assert_eq!(sddl.matches("(A;").count(), 3);
        assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"));
        assert!(sddl.contains(";;;S-1-5-21-1-2-3-1001)"));
        assert!(
            !sddl.contains(";;;WD)") && !sddl.contains(";;;BU)"),
            "no Everyone or Users"
        );
    }

    #[test]
    fn the_current_user_has_a_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[test]
    fn a_restricted_folder_lets_ordinary_users_out_and_the_owner_in() {
        let dir = std::env::temp_dir().join(format!("winperf-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.db");
        std::fs::write(&file, b"data").unwrap();

        restrict_to_admins_and_user(&dir).unwrap();

        let listing = |p: &Path| {
            let out = Command::new("icacls").arg(p).output().unwrap();
            String::from_utf8_lossy(&out.stdout).to_string()
        };
        let folder = listing(&dir);
        assert!(folder.contains("NT AUTHORITY\\SYSTEM"), "{folder}");
        assert!(folder.contains("BUILTIN\\Administrators"), "{folder}");
        assert!(!folder.contains("BUILTIN\\Users"), "{folder}");
        assert!(!folder.contains("Everyone"), "{folder}");
        // The file below got the same list passed down, and the owner can still use it.
        let inside = listing(&file);
        assert!(!inside.contains("BUILTIN\\Users"), "{inside}");
        assert!(inside.contains("NT AUTHORITY\\SYSTEM"), "{inside}");
        assert_eq!(std::fs::read(&file).unwrap(), b"data");
        std::fs::write(&file, b"more").unwrap();
        // A file created later inherits it too.
        let later = dir.join("later.db");
        std::fs::write(&later, b"x").unwrap();
        assert!(!listing(&later).contains("BUILTIN\\Users"));

        // A protected list still lets the owner clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
