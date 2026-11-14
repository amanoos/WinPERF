//! File version-resource reader (product name, description, original filename, file version).

use crate::signatures::to_wide;
use std::ffi::c_void;
use std::path::Path;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::core::{PCWSTR, w};
use winperf_core::inventory::{FileVersionInfo, VersionReader};

pub struct WindowsVersionReader;

/// Query one string value from a version block under the given `lang+codepage` key.
fn query_string(block: &[u8], lang_cp: &str, name: &str) -> Option<String> {
    let sub: Vec<u16> = format!("\\StringFileInfo\\{lang_cp}\\{name}\0")
        .encode_utf16()
        .collect();
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `block` is a version block from GetFileVersionInfoW; `sub` is NUL-terminated;
    // the returned pointer (if any) points into `block`, which outlives this function.
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            PCWSTR(sub.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };
    if !ok.as_bool() || ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: VerQueryValueW reports `len` UTF-16 units at `ptr`, inside `block`.
    let units = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize) };
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    let s = String::from_utf16_lossy(&units[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// First `lang+codepage` from `\VarFileInfo\Translation`, formatted like `040904B0`.
fn first_translation(block: &[u8]) -> Option<String> {
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: as in `query_string`; static NUL-terminated sub-block name.
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            w!("\\VarFileInfo\\Translation"),
            &mut ptr,
            &mut len,
        )
    };
    if !ok.as_bool() || ptr.is_null() || len < 4 {
        return None;
    }
    // SAFETY: the translation table is `len` bytes (pairs of u16) inside `block`; we read the first pair.
    let (lang, cp) = unsafe {
        let p = ptr as *const u16;
        (p.read_unaligned(), p.add(1).read_unaligned())
    };
    Some(format!("{lang:04X}{cp:04X}"))
}

impl VersionReader for WindowsVersionReader {
    fn read(&self, path: &Path) -> FileVersionInfo {
        let wide = to_wide(path);
        // SAFETY: `wide` is a valid NUL-terminated path.
        let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
        if size == 0 {
            return FileVersionInfo::default();
        }
        let mut block = vec![0u8; size as usize];
        // SAFETY: `block` has `size` writable bytes.
        let read = unsafe {
            GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, block.as_mut_ptr().cast())
        };
        if read.is_err() {
            return FileVersionInfo::default();
        }
        // Try the file's own translation first, then common fallbacks.
        let mut keys: Vec<String> = first_translation(&block).into_iter().collect();
        keys.extend(["040904B0".to_string(), "040904E4".to_string()]);
        let get = |name: &str| keys.iter().find_map(|k| query_string(&block, k, name));
        FileVersionInfo {
            product_name: get("ProductName"),
            file_description: get("FileDescription"),
            original_filename: get("OriginalFilename"),
            file_version: get("FileVersion"),
        }
    }
}
