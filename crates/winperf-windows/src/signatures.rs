//! Authenticode verification via WinVerifyTrust, with catalog fallback.
//!
//! Many core Windows binaries (e.g. notepad.exe) carry no embedded signature and are instead
//! listed in a signed *catalog*. File-mode `WinVerifyTrust` reports those as "no signature"
//! (T2 finding), so on that result we look the file's hash up in the system catalogs.
//!
//! No network access: revocation checks are disabled and URL retrieval is cache-only.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::{PCWSTR, w};
use winperf_core::inventory::{SignatureStatus, SignatureVerifier};

const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
/// File missing/unreadable codes surfaced by WinVerifyTrust.
const CRYPT_E_FILE_ERROR: u32 = 0x8009_2003;
const FILE_NOT_FOUND: u32 = 0x8007_0002;
const PATH_NOT_FOUND: u32 = 0x8007_0003;
const ACCESS_DENIED: u32 = 0x8007_0005;

pub(crate) fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Verifies signatures with the operating system's trust provider.
pub struct WinTrustVerifier;

struct Outcome {
    code: u32,
    signer: Option<String>,
}

fn base_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

/// Run VERIFY then CLOSE on a prepared `WINTRUST_DATA`, extracting the signer while the state is open.
///
/// # Safety
/// `data` must have a valid union pointer (file or catalog info) that outlives this call.
unsafe fn run_wintrust(data: &mut WINTRUST_DATA) -> Outcome {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // SAFETY: `data` is a valid, initialised WINTRUST_DATA per this function's contract.
    let code =
        unsafe { WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void) }
            as u32;
    let signer = if code == 0 {
        // SAFETY: the state handle is valid until the CLOSE call below.
        unsafe { signer_name(data.hWVTStateData) }
    } else {
        None
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes the state opened above; same valid `data`.
    unsafe { WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void) };
    Outcome { code, signer }
}

/// Display name of the first signer's leaf certificate.
///
/// # Safety
/// `state` must be a WinVerifyTrust state handle from a successful VERIFY that is still open.
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    // SAFETY: `state` is open per this function's contract. WinTrust returns pointers into its own
    // state data, valid while the state is open, and every pointer is null-checked before use.
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        let written =
            CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
        if written <= 1 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..(written as usize - 1)]))
    }
}

fn verify_embedded(wide_path: &[u16]) -> Outcome {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        ..Default::default()
    };
    let mut data = base_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    // SAFETY: `file` outlives the call and `pFile` points at it.
    unsafe { run_wintrust(&mut data) }
}

struct FileHandle(HANDLE);
impl Drop for FileHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful CreateFileW and is closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct CatAdmin(isize);
impl Drop for CatAdmin {
    fn drop(&mut self) {
        // SAFETY: the context came from a successful CryptCATAdminAcquireContext2 and is released once.
        let _ = unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

/// Look the file up in the system catalogs (SHA-256 first, then SHA-1) and verify membership.
/// Returns `None` if the file is in no catalog.
fn verify_catalog(wide_path: &[u16]) -> Option<Outcome> {
    // SAFETY: valid NUL-terminated path; no security attributes or template.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .ok()?;
    let file = FileHandle(handle);

    for algorithm in [w!("SHA256"), w!("SHA1")] {
        let mut raw_admin: isize = 0;
        // SAFETY: out-pointer is valid; algorithm is a static NUL-terminated string.
        if unsafe { CryptCATAdminAcquireContext2(&mut raw_admin, None, algorithm, None, None) }
            .is_err()
        {
            continue;
        }
        let admin = CatAdmin(raw_admin);

        let mut hash_len = 0u32;
        // SAFETY: first call with a null buffer only queries the required size.
        let _ = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.0, file.0, &mut hash_len, None, None)
        };
        if hash_len == 0 {
            continue;
        }
        let mut hash = vec![0u8; hash_len as usize];
        // SAFETY: `hash` has `hash_len` bytes of writable storage.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.0,
                file.0,
                &mut hash_len,
                Some(hash.as_mut_ptr()),
                None,
            )
        }
        .is_err()
        {
            continue;
        }
        hash.truncate(hash_len as usize);

        // SAFETY: `hash` is a valid slice; no previous catalog context.
        let cat_info = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, None, None) };
        if cat_info == 0 {
            continue; // not in any catalog under this algorithm
        }

        let mut info = CATALOG_INFO {
            cbStruct: size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        // SAFETY: `info` is a properly sized out-structure.
        let got_info = unsafe { CryptCATCatalogInfoFromContext(cat_info, &mut info, 0) };
        let outcome = if got_info.is_ok() {
            // Member tag = upper-case hex of the hash, as UTF-16.
            let tag: Vec<u16> = hash
                .iter()
                .flat_map(|b| format!("{b:02X}").encode_utf16().collect::<Vec<_>>())
                .chain(Some(0))
                .collect();
            let mut catalog = WINTRUST_CATALOG_INFO {
                cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wide_path.as_ptr()),
                hMemberFile: file.0,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash.len() as u32,
                hCatAdmin: admin.0,
                ..Default::default()
            };
            let mut data = base_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous.pCatalog = &mut catalog;
            // SAFETY: `catalog`, `info`, `tag`, `hash` and the handles all outlive the call.
            Some(unsafe { run_wintrust(&mut data) })
        } else {
            None
        };
        // SAFETY: releases the catalog context obtained above, once.
        let _ = unsafe { CryptCATAdminReleaseCatalogContext(admin.0, cat_info, 0) };
        if outcome.is_some() {
            return outcome;
        }
    }
    None
}

fn to_status(o: Outcome) -> SignatureStatus {
    match o.code {
        0 => SignatureStatus::Valid {
            signer: o.signer.unwrap_or_default(),
        },
        c => SignatureStatus::Invalid { code: c },
    }
}

impl SignatureVerifier for WinTrustVerifier {
    fn verify(&self, path: &Path) -> SignatureStatus {
        let wide = to_wide(path);
        let embedded = verify_embedded(&wide);
        match embedded.code {
            0 => to_status(embedded),
            CRYPT_E_FILE_ERROR | FILE_NOT_FOUND | PATH_NOT_FOUND | ACCESS_DENIED => {
                SignatureStatus::Unreadable
            }
            TRUST_E_NOSIGNATURE | TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN => {
                match verify_catalog(&wide) {
                    Some(c) => to_status(c),
                    None => SignatureStatus::NotSigned,
                }
            }
            other => SignatureStatus::Invalid { code: other },
        }
    }
}
