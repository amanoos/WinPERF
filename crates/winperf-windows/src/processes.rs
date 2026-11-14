//! Live process enumeration (PRD FR-003): Toolhelp snapshot plus per-process details.
//!
//! Access-denied is normal (T2: ~26% of processes unreadable without elevation), so every
//! detail is independently optional. Processes that vanish mid-scan are flagged `exited`.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, UNICODE_STRING};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, LookupAccountSidW, PSID, SID_NAME_USE, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};
use winperf_core::inventory::{ProcessSource, RawProcess};

/// `OpenProcess` fails with ERROR_INVALID_PARAMETER (87) when the PID no longer exists.
const HRESULT_INVALID_PARAMETER: i32 = 0x8007_0057_u32 as i32;
/// Exit code reported for a process that is still running.
const STILL_ACTIVE: u32 = 259;

/// Enumerates running processes.
#[derive(Default)]
pub struct WindowsProcessSource {
    /// Command lines may contain secrets (NFR-003), so they are only read when asked for.
    pub collect_command_line: bool,
}

pub(crate) struct OwnedHandle(pub(crate) HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful Open*/Create* call and is closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(crate) fn snapshot() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    // SAFETY: plain snapshot request; the handle is wrapped for closing below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return out;
    };
    let snap = OwnedHandle(snap);
    let mut e = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `e.dwSize` is set and `e` outlives the calls.
    let mut more = unsafe { Process32FirstW(snap.0, &mut e) }.is_ok();
    while more {
        let end = e
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(e.szExeFile.len());
        out.push((
            e.th32ProcessID,
            e.th32ParentProcessID,
            String::from_utf16_lossy(&e.szExeFile[..end]),
        ));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap.0, &mut e) }.is_ok();
    }
    out
}

fn filetime_u64(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

fn image_path(h: HANDLE, buf: &mut [u16]) -> Option<PathBuf> {
    let mut len = buf.len() as u32;
    // SAFETY: `buf` has `len` writable UTF-16 units; `h` is a live process handle.
    unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }
        .ok()?;
    Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// Owner of the process as `DOMAIN\name`; account lookups are cached per SID.
fn user_name(h: HANDLE, cache: &mut HashMap<Vec<u8>, Option<String>>) -> Option<String> {
    let mut token = HANDLE::default();
    // SAFETY: `h` is a live process handle; `token` is a valid out-pointer.
    unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut token) }.ok()?;
    let token = OwnedHandle(token);

    let mut needed = 0u32;
    // SAFETY: size query only (null buffer).
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    // u64 backing keeps the TOKEN_USER structure suitably aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` provides at least `needed` writable bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            needed,
            &mut needed,
        )
    }
    .ok()?;

    // SAFETY: GetTokenInformation(TokenUser) filled `buf` with a TOKEN_USER whose SID points into it.
    let sid: PSID = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` is a valid SID inside `buf`; GetLengthSid returns its byte length.
    let sid_bytes: Vec<u8> = unsafe {
        let len = GetLengthSid(sid) as usize;
        std::slice::from_raw_parts(sid.0 as *const u8, len).to_vec()
    };
    if let Some(hit) = cache.get(&sid_bytes) {
        return hit.clone();
    }

    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: both buffers are writable with the lengths passed; `sid` is valid.
    let looked_up = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }
    .is_ok();
    let result = looked_up.then(|| {
        let n = String::from_utf16_lossy(&name[..name_len as usize]);
        let d = String::from_utf16_lossy(&domain[..domain_len as usize]);
        if d.is_empty() { n } else { format!("{d}\\{n}") }
    });
    cache.insert(sid_bytes, result.clone());
    result
}

fn command_line(h: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    // SAFETY: size query only; a zero-length buffer is expected to fail with a length-mismatch status.
    let _ = unsafe {
        NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed < size_of::<UNICODE_STRING>() as u32 {
        return None;
    }
    // u64 backing keeps the UNICODE_STRING (with a pointer member) aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` provides at least `needed` writable bytes.
    let status = unsafe {
        NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if status.0 < 0 {
        return None;
    }
    // SAFETY: on success `buf` holds a UNICODE_STRING whose Buffer points at `Length` bytes inside `buf`.
    let text = unsafe {
        let us = &*buf.as_ptr().cast::<UNICODE_STRING>();
        if us.Buffer.is_null() || us.Length == 0 {
            return None;
        }
        std::slice::from_raw_parts(us.Buffer.0, (us.Length / 2) as usize)
    };
    Some(String::from_utf16_lossy(text))
}

impl WindowsProcessSource {
    pub(crate) fn inspect(
        &self,
        pid: u32,
        parent_pid: u32,
        name: String,
        path_buf: &mut [u16],
        users: &mut HashMap<Vec<u8>, Option<String>>,
    ) -> RawProcess {
        let mut raw = RawProcess {
            pid,
            parent_pid,
            name,
            ..Default::default()
        };
        let mut session = 0u32;
        // SAFETY: valid out-pointer.
        if unsafe { ProcessIdToSessionId(pid, &mut session) }.is_ok() {
            raw.session_id = Some(session);
        }

        // SAFETY: plain open for limited query; the result is wrapped for closing.
        let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(h) => OwnedHandle(h),
            Err(e) => {
                // No such PID any more => it exited between the snapshot and now. Anything else
                // (access denied, protected process) just leaves the details unavailable.
                raw.exited = e.code().0 == HRESULT_INVALID_PARAMETER;
                return raw;
            }
        };

        let mut code = 0u32;
        // SAFETY: live handle, valid out-pointer.
        if unsafe { GetExitCodeProcess(handle.0, &mut code) }.is_ok() && code != STILL_ACTIVE {
            raw.exited = true; // handle opened on a process that has already terminated
            return raw;
        }

        let (mut c, mut x, mut k, mut u) = Default::default();
        // SAFETY: live handle, valid out-pointers.
        if unsafe { GetProcessTimes(handle.0, &mut c, &mut x, &mut k, &mut u) }.is_ok() {
            raw.start_time = Some(filetime_u64(c));
        }
        raw.exe_path = image_path(handle.0, path_buf);
        raw.user = user_name(handle.0, users);
        if self.collect_command_line {
            raw.command_line = command_line(handle.0);
        }
        raw
    }
}

impl ProcessSource for WindowsProcessSource {
    fn list(&self) -> Vec<RawProcess> {
        let mut path_buf = vec![0u16; 32_768];
        let mut users = HashMap::new();
        snapshot()
            .into_iter()
            .filter(|(pid, _, _)| *pid != 0) // System Idle Process is not a real process
            .map(|(pid, ppid, name)| self.inspect(pid, ppid, name, &mut path_buf, &mut users))
            .collect()
    }
}
