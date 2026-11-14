//! Executable metadata and publisher classification (PRD FR-002).
//!
//! Classification is driven **only** by a valid signature whose signer is Microsoft. File names,
//! install paths and product names never establish Microsoft identity.

use crate::Classification;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// Result of verifying a file's Authenticode signature (embedded or catalog).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Valid, trusted signature. `signer` is the signing certificate's display name.
    Valid { signer: String },
    /// No signature at all (neither embedded nor in a catalog).
    NotSigned,
    /// A signature exists but is not valid/trusted (tampered, expired, untrusted root, ...).
    /// `code` is the Windows trust result (HRESULT).
    Invalid { code: u32 },
    /// The file could not be read or verified, so the state is unknown.
    Unreadable,
}

/// Signer names that identify Microsoft as publisher. Exact (case-insensitive) match only:
/// substring matching would accept look-alikes such as "Microsoft Corporation Ltd".
const MICROSOFT_SIGNERS: &[&str] = &[
    "microsoft corporation",
    "microsoft windows",
    "microsoft windows publisher",
];

pub fn is_microsoft_signer(signer: &str) -> bool {
    let s = signer.trim().to_lowercase();
    MICROSOFT_SIGNERS.contains(&s.as_str())
}

/// Map a signature result to a publisher classification.
pub fn classify(status: &SignatureStatus) -> Classification {
    match status {
        SignatureStatus::Valid { signer } if is_microsoft_signer(signer) => {
            Classification::MicrosoftOfficial
        }
        SignatureStatus::Valid { .. } => Classification::ThirdPartyOfficial,
        SignatureStatus::NotSigned | SignatureStatus::Invalid { .. } => Classification::Unsigned,
        SignatureStatus::Unreadable => Classification::Unknown,
    }
}

pub trait SignatureVerifier {
    fn verify(&self, path: &Path) -> SignatureStatus;
}

/// Version-resource fields (all optional: many files have none).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileVersionInfo {
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub original_filename: Option<String>,
    pub file_version: Option<String>,
}

pub trait VersionReader {
    fn read(&self, path: &Path) -> FileVersionInfo;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableInfo {
    pub path: PathBuf,
    pub version: FileVersionInfo,
    pub signature: SignatureStatus,
    pub classification: Classification,
}

pub fn inspect(
    path: &Path,
    verifier: &dyn SignatureVerifier,
    versions: &dyn VersionReader,
) -> ExecutableInfo {
    let signature = verifier.verify(path);
    ExecutableInfo {
        path: path.to_path_buf(),
        version: versions.read(path),
        classification: classify(&signature),
        signature,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileId {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

/// Caches verification results by (path, size, modified time). Verification is slow
/// (~70 ms for signed files, measured in T2), so repeated sightings must not re-verify.
/// A changed file (new size or mtime) is re-verified. `Unreadable` results are not cached.
pub struct CachedVerifier<V> {
    inner: V,
    cache: Mutex<HashMap<FileId, SignatureStatus>>,
}

impl<V: SignatureVerifier> CachedVerifier<V> {
    pub fn new(inner: V) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl<V: SignatureVerifier> SignatureVerifier for CachedVerifier<V> {
    fn verify(&self, path: &Path) -> SignatureStatus {
        let Ok(meta) = std::fs::metadata(path) else {
            return SignatureStatus::Unreadable;
        };
        let id = FileId {
            path: path.to_path_buf(),
            len: meta.len(),
            modified: meta.modified().ok(),
        };
        if let Some(hit) = self.cache.lock().expect("cache poisoned").get(&id) {
            return hit.clone();
        }
        let result = self.inner.verify(path);
        if result != SignatureStatus::Unreadable {
            self.cache
                .lock()
                .expect("cache poisoned")
                .insert(id, result.clone());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs::File;
    use std::time::Duration;

    fn valid(s: &str) -> SignatureStatus {
        SignatureStatus::Valid { signer: s.into() }
    }

    #[test]
    fn microsoft_signers_are_matched_exactly() {
        for ok in [
            "Microsoft Corporation",
            "microsoft corporation",
            " Microsoft Windows ",
            "Microsoft Windows Publisher",
        ] {
            assert!(is_microsoft_signer(ok), "{ok}");
        }
        for bad in [
            "Microsoft Corporation Ltd",
            "Not Microsoft Corporation",
            "Microsoft",
            "Micr0soft Corporation",
            "",
        ] {
            assert!(!is_microsoft_signer(bad), "{bad}");
        }
    }

    #[test]
    fn classification_follows_signature_only() {
        assert_eq!(
            classify(&valid("Microsoft Corporation")),
            Classification::MicrosoftOfficial
        );
        assert_eq!(
            classify(&valid("JetBrains s.r.o.")),
            Classification::ThirdPartyOfficial
        );
        assert_eq!(
            classify(&SignatureStatus::NotSigned),
            Classification::Unsigned
        );
        assert_eq!(
            classify(&SignatureStatus::Unreadable),
            Classification::Unknown
        );
    }

    #[test]
    fn a_broken_microsoft_signature_is_not_microsoft() {
        // e.g. TRUST_E_BAD_DIGEST: file was modified after signing.
        assert_eq!(
            classify(&SignatureStatus::Invalid { code: 0x8009_6010 }),
            Classification::Unsigned
        );
    }

    struct Counting<'a>(&'a Cell<u32>, SignatureStatus);
    impl SignatureVerifier for Counting<'_> {
        fn verify(&self, _: &Path) -> SignatureStatus {
            self.0.set(self.0.get() + 1);
            self.1.clone()
        }
    }

    fn temp_file(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("winperf-t6-{}-{tag}", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        p
    }

    #[test]
    fn cache_verifies_once_and_reverifies_when_file_changes() {
        let calls = Cell::new(0);
        let v = CachedVerifier::new(Counting(&calls, valid("Acme")));
        let p = temp_file("cache");

        assert_eq!(v.verify(&p), valid("Acme"));
        assert_eq!(v.verify(&p), valid("Acme"));
        assert_eq!(calls.get(), 1, "second lookup must hit the cache");

        // Same size, newer mtime -> re-verified.
        let f = File::options().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();
        drop(f);
        v.verify(&p);
        assert_eq!(calls.get(), 2);

        // New size -> re-verified.
        std::fs::write(&p, b"abcdef").unwrap();
        v.verify(&p);
        assert_eq!(calls.get(), 3);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_is_unreadable_and_not_cached() {
        let calls = Cell::new(0);
        let v = CachedVerifier::new(Counting(&calls, valid("Acme")));
        let missing = std::env::temp_dir().join("winperf-t6-definitely-missing.exe");
        assert_eq!(v.verify(&missing), SignatureStatus::Unreadable);
        assert_eq!(
            calls.get(),
            0,
            "inner verifier is not called for missing files"
        );
    }

    struct FixedVersion;
    impl VersionReader for FixedVersion {
        fn read(&self, _: &Path) -> FileVersionInfo {
            FileVersionInfo {
                product_name: Some("Microsoft Edge".into()),
                ..Default::default()
            }
        }
    }

    #[test]
    fn product_name_alone_never_makes_something_microsoft() {
        let calls = Cell::new(0);
        let info = inspect(
            Path::new("C:\\x\\microsoft.exe"),
            &Counting(&calls, SignatureStatus::NotSigned),
            &FixedVersion,
        );
        assert_eq!(info.version.product_name.as_deref(), Some("Microsoft Edge"));
        assert_eq!(info.classification, Classification::Unsigned);
    }
}
