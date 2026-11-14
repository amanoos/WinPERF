//! Live signature/version tests against real Windows binaries (T6 acceptance criteria).

use std::path::{Path, PathBuf};
use winperf_core::Classification;
use winperf_core::inventory::{
    SignatureStatus, SignatureVerifier, VersionReader, classify, inspect,
};
use winperf_windows::{WinTrustVerifier, WindowsVersionReader};

const NOTEPAD: &str = r"C:\Windows\System32\notepad.exe";
const KERNEL32: &str = r"C:\Windows\System32\kernel32.dll";

fn class_of(path: &Path) -> Classification {
    classify(&WinTrustVerifier.verify(path))
}

fn temp_copy(tag: &str, src: &Path) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winperf-t6-live-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dst = dir.join(src.file_name().unwrap());
    std::fs::copy(src, &dst).unwrap();
    dst
}

#[test]
fn catalog_signed_notepad_is_microsoft() {
    // notepad.exe has no embedded signature (T2): this only passes with catalog verification.
    let status = WinTrustVerifier.verify(Path::new(NOTEPAD));
    assert!(
        matches!(status, SignatureStatus::Valid { .. }),
        "got {status:?}"
    );
    assert_eq!(classify(&status), Classification::MicrosoftOfficial);
}

#[test]
fn embedded_signature_dll_is_microsoft() {
    assert_eq!(
        class_of(Path::new(KERNEL32)),
        Classification::MicrosoftOfficial
    );
}

#[test]
fn unsigned_binary_is_unsigned() {
    let exe = std::env::current_exe().unwrap(); // this test binary: never signed
    assert_eq!(WinTrustVerifier.verify(&exe), SignatureStatus::NotSigned);
    assert_eq!(class_of(&exe), Classification::Unsigned);
}

#[test]
fn a_file_named_microsoft_is_not_microsoft() {
    let fake = temp_copy("fake", &std::env::current_exe().unwrap());
    let renamed = fake.with_file_name("microsoft.exe");
    std::fs::rename(&fake, &renamed).unwrap();
    assert_eq!(class_of(&renamed), Classification::Unsigned);
    let _ = std::fs::remove_dir_all(renamed.parent().unwrap());
}

#[test]
fn tampered_copy_of_a_microsoft_binary_is_not_microsoft() {
    let copy = temp_copy("tamper", Path::new(NOTEPAD));
    // An untouched copy is still the same catalog member, so it stays Microsoft: identity follows content, not path.
    assert_eq!(class_of(&copy), Classification::MicrosoftOfficial);

    let mut bytes = std::fs::read(&copy).unwrap();
    bytes[2048] ^= 0xFF;
    std::fs::write(&copy, bytes).unwrap();
    assert_ne!(class_of(&copy), Classification::MicrosoftOfficial);
    let _ = std::fs::remove_dir_all(copy.parent().unwrap());
}

#[test]
fn missing_file_is_unknown() {
    let status = WinTrustVerifier.verify(Path::new(r"C:\definitely\missing\nothing.exe"));
    assert_eq!(status, SignatureStatus::Unreadable);
    assert_eq!(classify(&status), Classification::Unknown);
}

#[test]
fn third_party_signed_binary_is_third_party_when_present() {
    let candidates = [
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
    ];
    let Some(p) = candidates.iter().map(Path::new).find(|p| p.exists()) else {
        eprintln!("no known third-party signed binary installed; skipping");
        return;
    };
    assert_eq!(class_of(p), Classification::ThirdPartyOfficial, "{p:?}");
}

#[test]
fn version_resources_are_read() {
    let v = WindowsVersionReader.read(Path::new(NOTEPAD));
    assert!(v.file_version.is_some(), "{v:?}");
    assert!(v.original_filename.is_some(), "{v:?}");
    assert!(v.file_description.is_some(), "{v:?}");
}

#[test]
fn file_without_version_info_yields_empty_fields() {
    let v = WindowsVersionReader.read(Path::new(r"C:\definitely\missing\nothing.exe"));
    assert_eq!(v, Default::default());
}

#[test]
fn inspect_combines_metadata_and_classification() {
    let info = inspect(Path::new(NOTEPAD), &WinTrustVerifier, &WindowsVersionReader);
    assert_eq!(info.classification, Classification::MicrosoftOfficial);
    assert!(info.version.file_version.is_some());
}
