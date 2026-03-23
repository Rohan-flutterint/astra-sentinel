use std::fs;
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use zip::ZipArchive;

#[derive(Clone, Debug)]
pub struct FeedDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub source_url: &'static str,
    pub archive_url: &'static str,
}

#[derive(Clone, Debug)]
pub struct FeedStatus {
    pub feed: FeedDefinition,
    pub rule_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct FeedSyncSummary {
    pub synced_feeds: usize,
    pub total_rules: usize,
    pub destination: PathBuf,
    pub per_feed: Vec<FeedStatus>,
}

pub fn curated_feeds() -> Vec<FeedDefinition> {
    vec![
        FeedDefinition {
            id: "yara-rules",
            name: "Yara-Rules",
            description: "Large community-maintained public YARA repository.",
            source_url: "https://github.com/Yara-Rules/rules",
            archive_url: "https://codeload.github.com/Yara-Rules/rules/zip/refs/heads/master",
        },
        FeedDefinition {
            id: "signature-base",
            name: "Neo23x0 signature-base",
            description: "Widely used YARA and IOC repository curated for defenders.",
            source_url: "https://github.com/Neo23x0/signature-base",
            archive_url: "https://codeload.github.com/Neo23x0/signature-base/zip/refs/heads/master",
        },
    ]
}

pub fn default_feed_rules_dir() -> PathBuf {
    PathBuf::from("feeds").join("rules")
}

pub fn sync_curated_feeds(base_rules_dir: &Path) -> Result<FeedSyncSummary> {
    fs::create_dir_all(base_rules_dir)
        .with_context(|| format!("could not create {}", base_rules_dir.display()))?;

    let client = Client::builder()
        .user_agent("astra-sentinel/0.3.0")
        .build()
        .context("failed to build HTTP client")?;

    let mut summary = FeedSyncSummary {
        destination: base_rules_dir.to_path_buf(),
        ..Default::default()
    };

    for feed in curated_feeds() {
        let feed_dir = base_rules_dir.join(feed.id);
        if feed_dir.exists() {
            fs::remove_dir_all(&feed_dir)
                .with_context(|| format!("failed to clean {}", feed_dir.display()))?;
        }
        fs::create_dir_all(&feed_dir)
            .with_context(|| format!("failed to create {}", feed_dir.display()))?;

        let response = client
            .get(feed.archive_url)
            .send()
            .with_context(|| format!("failed to download {}", feed.archive_url))?
            .error_for_status()
            .with_context(|| format!("download failed for {}", feed.archive_url))?;

        let bytes = response.bytes().context("failed to read archive bytes")?;
        let cursor = Cursor::new(bytes);
        let mut archive = ZipArchive::new(cursor).context("failed to open ZIP archive")?;

        let mut rule_count = 0;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .context("failed to read ZIP entry")?;
            if !entry.is_file() {
                continue;
            }

            let entry_path = match entry.enclosed_name() {
                Some(path) => path.to_path_buf(),
                None => continue,
            };

            if !has_rule_extension(&entry_path) {
                continue;
            }

            let relative_path = strip_archive_root(&entry_path);
            let safe_relative = sanitize_relative_path(&relative_path);
            if safe_relative.as_os_str().is_empty() {
                continue;
            }

            let destination = feed_dir.join(safe_relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }

            let mut output = fs::File::create(&destination)
                .with_context(|| format!("failed to create {}", destination.display()))?;
            std::io::copy(&mut entry, &mut output)
                .with_context(|| format!("failed to write {}", destination.display()))?;
            rule_count += 1;
        }

        summary.synced_feeds += 1;
        summary.total_rules += rule_count;
        summary.per_feed.push(FeedStatus { feed, rule_count });
    }

    Ok(summary)
}

fn has_rule_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "yar" | "yara"))
        .unwrap_or(false)
}

fn strip_archive_root(path: &Path) -> PathBuf {
    let mut components = path.components();
    let _ = components.next();
    components.as_path().to_path_buf()
}

fn sanitize_relative_path(path: &Path) -> PathBuf {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        if let Component::Normal(part) = component {
            sanitized.push(part);
        }
    }
    sanitized
}
