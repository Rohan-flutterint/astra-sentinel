use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    pub const fn variants() -> [Self; 3] {
        [Self::Md5, Self::Sha1, Self::Sha256]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    pub const fn expected_hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for HashAlgorithm {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            other => bail!("unsupported hash type: {other}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub hash: String,
    pub threat_name: String,
}

#[derive(Default)]
pub struct SignatureDb {
    entries: HashMap<String, Signature>,
}

impl SignatureDb {
    pub fn load(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)
            .with_context(|| format!("could not open signature database {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut entries = HashMap::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read signature database line {} from {}",
                    line_no + 1,
                    path.display()
                )
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<_> = trimmed.splitn(3, '|').map(str::trim).collect();
            if parts.len() != 3 {
                continue;
            }

            let signature = Signature {
                hash: parts[1].to_ascii_lowercase(),
                threat_name: parts[2].to_string(),
            };
            entries.insert(signature.hash.clone(), signature);
        }

        Ok(Self { entries })
    }

    pub fn lookup(&self, hash: &str) -> Option<&Signature> {
        self.entries.get(&hash.to_ascii_lowercase())
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

pub fn add_signature(
    db_path: &Path,
    hash_type: HashAlgorithm,
    hash_value: &str,
    threat_name: &str,
) -> Result<()> {
    let normalized_hash = hash_value.trim().to_ascii_lowercase();
    let normalized_name = threat_name.trim();

    if normalized_name.is_empty() {
        bail!("threat name is required");
    }
    if normalized_hash.len() != hash_type.expected_hex_len() {
        bail!(
            "{} hashes must be {} hexadecimal characters",
            hash_type,
            hash_type.expected_hex_len()
        );
    }
    if !normalized_hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("hash must contain only hexadecimal characters");
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(db_path)
        .with_context(|| format!("could not open {} for writing", db_path.display()))?;

    writeln!(
        file,
        "{}|{}|{}",
        hash_type, normalized_hash, normalized_name
    )
    .with_context(|| format!("failed to append signature to {}", db_path.display()))?;

    Ok(())
}
