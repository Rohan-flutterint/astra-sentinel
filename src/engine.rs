use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::Sender,
    Arc,
};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::signatures::{HashAlgorithm, SignatureDb};
use crate::yara::{YaraMatch, YaraScanner};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Clean,
    Malicious,
    Error,
}

impl Verdict {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::Malicious => "MALICIOUS",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub detected: bool,
    pub match_type: Option<HashAlgorithm>,
    pub match_hash: Option<String>,
    pub threat_name: Option<String>,
    pub yara_matches: Vec<YaraMatch>,
    pub verdict: Verdict,
    pub scan_time: Duration,
    pub error: Option<String>,
}

impl ScanResult {
    pub fn error(path: PathBuf, message: String) -> Self {
        Self {
            file_path: path,
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            detected: false,
            match_type: None,
            match_hash: None,
            threat_name: None,
            yara_matches: Vec::new(),
            verdict: Verdict::Error,
            scan_time: Duration::default(),
            error: Some(message),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub hash_detections: usize,
    pub yara_detections: usize,
    pub errors: usize,
    pub skipped_files: usize,
    pub elapsed: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct ScanPolicy {
    pub skip_hidden_paths: bool,
    pub max_file_size_bytes: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum ScanTarget {
    File(PathBuf),
    Directory(PathBuf),
}

#[derive(Clone, Debug)]
pub struct ScanRequest {
    pub target: ScanTarget,
    pub database_path: PathBuf,
    pub rules_path: Option<PathBuf>,
    pub policy: ScanPolicy,
}

#[derive(Debug)]
pub enum ScanEvent {
    Started {
        total: usize,
        signature_count: usize,
        rule_files: usize,
    },
    FileScanned(ScanResult),
    Failed(String),
    Finished {
        summary: ScanSummary,
        cancelled: bool,
    },
}

pub fn run_scan(request: ScanRequest, sender: Sender<ScanEvent>, cancel_flag: Arc<AtomicBool>) {
    if let Err(error) = execute_scan(request, &sender, &cancel_flag) {
        let _ = sender.send(ScanEvent::Failed(error.to_string()));
    }
}

fn execute_scan(
    request: ScanRequest,
    sender: &Sender<ScanEvent>,
    cancel_flag: &AtomicBool,
) -> Result<()> {
    let started = Instant::now();
    let database = SignatureDb::load(&request.database_path)?;
    let (yara_scanner, rule_files) = if let Some(path) = &request.rules_path {
        let (scanner, count) = YaraScanner::load(path)?;
        (Some(scanner), count)
    } else {
        (None, 0)
    };

    sender.send(ScanEvent::Started {
        total: match &request.target {
            ScanTarget::File(_) => 1,
            ScanTarget::Directory(_) => 0,
        },
        signature_count: database.count(),
        rule_files,
    })?;

    let mut summary = ScanSummary::default();
    let mut cancelled = false;

    match &request.target {
        ScanTarget::File(path) => {
            if !path.is_file() {
                bail!("scan target {} is not a file", path.display());
            }

            if cancel_flag.load(Ordering::Relaxed) {
                cancelled = true;
            } else if should_skip_for_size(path, &request.policy)? {
                summary.skipped_files += 1;
            } else {
                let result = scan_file(path, &database, yara_scanner.as_ref());
                update_summary(&mut summary, &result);
                sender.send(ScanEvent::FileScanned(result))?;
            }
        }
        ScanTarget::Directory(path) => {
            if !path.is_dir() {
                bail!("scan target {} is not a directory", path.display());
            }

            for entry in WalkDir::new(path)
                .into_iter()
                .filter_entry(|entry| !should_skip_hidden(entry.path(), &request.policy))
            {
                if cancel_flag.load(Ordering::Relaxed) {
                    cancelled = true;
                    break;
                }

                match entry {
                    Ok(entry) => {
                        if !entry.file_type().is_file() {
                            continue;
                        }
                        if should_skip_for_size(entry.path(), &request.policy)? {
                            summary.skipped_files += 1;
                            continue;
                        }
                        let result = scan_file(entry.path(), &database, yara_scanner.as_ref());
                        update_summary(&mut summary, &result);
                        sender.send(ScanEvent::FileScanned(result))?;
                    }
                    Err(error) => {
                        let location = error
                            .path()
                            .map(Path::to_path_buf)
                            .unwrap_or_else(|| path.clone());
                        let result = ScanResult::error(location, error.to_string());
                        update_summary(&mut summary, &result);
                        sender.send(ScanEvent::FileScanned(result))?;
                    }
                }
            }
        }
    }

    summary.elapsed = started.elapsed();
    sender.send(ScanEvent::Finished { summary, cancelled })?;
    Ok(())
}

fn update_summary(summary: &mut ScanSummary, result: &ScanResult) {
    summary.files_scanned += 1;
    if result.detected {
        summary.hash_detections += 1;
    }
    if !result.yara_matches.is_empty() {
        summary.yara_detections += 1;
    }
    if matches!(result.verdict, Verdict::Error) {
        summary.errors += 1;
    }
}

fn scan_file(
    path: &Path,
    database: &SignatureDb,
    yara_scanner: Option<&YaraScanner>,
) -> ScanResult {
    let started = Instant::now();
    let mut result = ScanResult {
        file_path: path.to_path_buf(),
        md5: String::new(),
        sha1: String::new(),
        sha256: String::new(),
        detected: false,
        match_type: None,
        match_hash: None,
        threat_name: None,
        yara_matches: Vec::new(),
        verdict: Verdict::Clean,
        scan_time: Duration::default(),
        error: None,
    };

    match hash_file(path) {
        Ok((md5, sha1, sha256)) => {
            result.md5 = md5;
            result.sha1 = sha1;
            result.sha256 = sha256;
        }
        Err(error) => {
            result.verdict = Verdict::Error;
            result.scan_time = started.elapsed();
            result.error = Some(error.to_string());
            return result;
        }
    }

    for (algorithm, value) in [
        (HashAlgorithm::Sha256, result.sha256.as_str()),
        (HashAlgorithm::Sha1, result.sha1.as_str()),
        (HashAlgorithm::Md5, result.md5.as_str()),
    ] {
        if let Some(signature) = database.lookup(value) {
            result.detected = true;
            result.match_type = Some(algorithm);
            result.match_hash = Some(value.to_string());
            result.threat_name = Some(signature.threat_name.clone());
            result.verdict = Verdict::Malicious;
            break;
        }
    }

    if let Some(scanner) = yara_scanner {
        match scanner.scan_file(path) {
            Ok(matches) => {
                if !matches.is_empty() {
                    result.yara_matches = matches;
                    result.verdict = Verdict::Malicious;
                }
            }
            Err(error) => {
                result.verdict = Verdict::Error;
                result.error = Some(error.to_string());
            }
        }
    }

    result.scan_time = started.elapsed();
    result
}

fn should_skip_hidden(path: &Path, policy: &ScanPolicy) -> bool {
    policy.skip_hidden_paths && is_hidden_name(path.file_name())
}

fn is_hidden_name(name: Option<&OsStr>) -> bool {
    name.and_then(OsStr::to_str)
        .map(|value| value.starts_with('.') && value != "." && value != "..")
        .unwrap_or(false)
}

fn should_skip_for_size(path: &Path, policy: &ScanPolicy) -> Result<bool> {
    let Some(limit) = policy.max_file_size_bytes else {
        return Ok(false);
    };

    let metadata =
        std::fs::metadata(path).with_context(|| format!("could not stat {}", path.display()))?;
    Ok(metadata.is_file() && metadata.len() > limit)
}

fn hash_file(path: &Path) -> Result<(String, String, String)> {
    let mut file =
        File::open(path).with_context(|| format!("could not open file {}", path.display()))?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
    }

    Ok((
        format!("{:x}", md5.finalize()),
        format!("{:x}", sha1.finalize()),
        format!("{:x}", sha256.finalize()),
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use super::{
        is_hidden_name, should_skip_hidden, update_summary, ScanPolicy, ScanResult, ScanSummary,
        Verdict,
    };

    #[test]
    fn summary_counts_error_results() {
        let mut summary = ScanSummary::default();
        let result = ScanResult {
            file_path: "sample.bin".into(),
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            detected: false,
            match_type: None,
            match_hash: None,
            threat_name: None,
            yara_matches: Vec::new(),
            verdict: Verdict::Error,
            scan_time: Default::default(),
            error: Some("boom".to_string()),
        };

        update_summary(&mut summary, &result);
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.errors, 1);
    }

    #[test]
    fn hidden_paths_are_detected() {
        let policy = ScanPolicy {
            skip_hidden_paths: true,
            max_file_size_bytes: None,
        };
        assert!(is_hidden_name(Some(OsStr::new(".git"))));
        assert!(should_skip_hidden(Path::new("/tmp/.git"), &policy));
        assert!(!should_skip_hidden(Path::new("/tmp/src"), &policy));
    }
}
