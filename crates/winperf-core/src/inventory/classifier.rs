//! Signature classification off the sampling path.
//!
//! Verifying a signed executable costs ~70 ms and a cold scan of a whole machine takes seconds
//! (measured in T2/T7), far too slow for the sampling tick. The engine therefore *submits* paths
//! and later *polls* for results; a worker thread does the slow part.

use super::executable::{ExecutableInfo, SignatureVerifier, VersionReader, inspect};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

/// Non-blocking classification service: `submit` never waits for verification.
pub trait ExecutableClassifier {
    /// Ask for a path to be classified. Resubmitting a path still in flight is a no-op.
    fn submit(&mut self, path: PathBuf);
    /// Results that have finished since the last poll. Never blocks.
    fn poll(&mut self) -> Vec<ExecutableInfo>;
}

/// Runs verification and version-resource reads on a dedicated thread.
pub struct BackgroundClassifier {
    work: Option<mpsc::Sender<PathBuf>>,
    results: mpsc::Receiver<ExecutableInfo>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    in_flight: HashSet<PathBuf>,
}

impl BackgroundClassifier {
    pub fn spawn<V, R>(verifier: V, versions: R) -> Self
    where
        V: SignatureVerifier + Send + 'static,
        R: VersionReader + Send + 'static,
    {
        let (work_tx, work_rx) = mpsc::channel::<PathBuf>();
        let (result_tx, result_rx) = mpsc::channel::<ExecutableInfo>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let worker = std::thread::Builder::new()
            .name("winperf-classifier".into())
            .spawn(move || {
                while let Ok(path) = work_rx.recv() {
                    if stop_flag.load(Ordering::Relaxed) {
                        break; // shutting down: don't grind through the backlog
                    }
                    let info = inspect(&path, &verifier, &versions);
                    if result_tx.send(info).is_err() {
                        break; // nobody is listening any more
                    }
                }
            })
            .expect("failed to spawn the classifier thread");
        Self {
            work: Some(work_tx),
            results: result_rx,
            stop,
            worker: Some(worker),
            in_flight: HashSet::new(),
        }
    }

    /// Paths submitted but not yet returned by `poll`.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }
}

impl ExecutableClassifier for BackgroundClassifier {
    fn submit(&mut self, path: PathBuf) {
        if self.in_flight.insert(path.clone())
            && let Some(tx) = &self.work
        {
            let _ = tx.send(path);
        }
    }

    fn poll(&mut self) -> Vec<ExecutableInfo> {
        let mut done = Vec::new();
        while let Ok(info) = self.results.try_recv() {
            self.in_flight.remove(&info.path);
            done.push(info);
        }
        done
    }
}

impl Drop for BackgroundClassifier {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.work = None; // closes the channel so the worker's recv() returns
        if let Some(handle) = self.worker.take() {
            let _ = handle.join(); // waits at most for the item being verified right now
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::executable::{FileVersionInfo, SignatureStatus};
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    struct Slow {
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }
    impl SignatureVerifier for Slow {
        fn verify(&self, _: &Path) -> SignatureStatus {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            SignatureStatus::Valid {
                signer: "Acme".into(),
            }
        }
    }
    struct NoVersions;
    impl VersionReader for NoVersions {
        fn read(&self, _: &Path) -> FileVersionInfo {
            FileVersionInfo::default()
        }
    }

    fn classifier(delay_ms: u64) -> (BackgroundClassifier, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = BackgroundClassifier::spawn(
            Slow {
                delay: Duration::from_millis(delay_ms),
                calls: Arc::clone(&calls),
            },
            NoVersions,
        );
        (c, calls)
    }

    fn wait_for(c: &mut BackgroundClassifier, want: usize) -> Vec<ExecutableInfo> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.len() < want && Instant::now() < deadline {
            got.extend(c.poll());
            std::thread::sleep(Duration::from_millis(5));
        }
        got
    }

    #[test]
    fn submit_returns_immediately_and_the_result_arrives_later() {
        let (mut c, _) = classifier(200);
        let started = Instant::now();
        c.submit(PathBuf::from("C:\\a.exe"));
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "submit blocked"
        );
        assert!(c.poll().is_empty(), "not finished yet");

        let got = wait_for(&mut c, 1);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, PathBuf::from("C:\\a.exe"));
        assert_eq!(
            got[0].classification,
            crate::Classification::ThirdPartyOfficial
        );
    }

    #[test]
    fn resubmitting_a_path_in_flight_verifies_it_once() {
        let (mut c, calls) = classifier(100);
        for _ in 0..5 {
            c.submit(PathBuf::from("C:\\same.exe"));
        }
        assert_eq!(c.in_flight(), 1);
        assert_eq!(wait_for(&mut c, 1).len(), 1);
        std::thread::sleep(Duration::from_millis(150));
        assert!(c.poll().is_empty(), "no duplicate result");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(c.in_flight(), 0);
    }

    #[test]
    fn a_finished_path_can_be_submitted_again() {
        let (mut c, calls) = classifier(1);
        c.submit(PathBuf::from("C:\\x.exe"));
        wait_for(&mut c, 1);
        c.submit(PathBuf::from("C:\\x.exe"));
        wait_for(&mut c, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn many_paths_all_come_back() {
        let (mut c, _) = classifier(1);
        for i in 0..20 {
            c.submit(PathBuf::from(format!("C:\\p{i}.exe")));
        }
        assert_eq!(wait_for(&mut c, 20).len(), 20);
    }

    #[test]
    fn dropping_with_a_long_backlog_does_not_wait_for_it() {
        let (mut c, calls) = classifier(100);
        for i in 0..100 {
            c.submit(PathBuf::from(format!("C:\\q{i}.exe"))); // ~10 s of work queued
        }
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        drop(c);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "drop took {:?}",
            started.elapsed()
        );
        assert!(
            calls.load(Ordering::SeqCst) < 10,
            "backlog should be abandoned"
        );
    }
}
