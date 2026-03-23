use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use walkdir::WalkDir;

#[derive(Clone, Debug)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub strings: Vec<YaraMatchString>,
}

#[derive(Clone, Debug)]
pub struct YaraMatchString {
    pub name: String,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct YaraScanner {
    rules_path: PathBuf,
    binary_path: PathBuf,
}

impl YaraScanner {
    pub fn load(path: &Path) -> Result<(Self, usize)> {
        let binary_path = find_yara_binary()?;
        let files = collect_rule_files(path)?;
        if files.is_empty() {
            bail!("no .yar or .yara files found at {}", path.display());
        }

        for file in &files {
            let output = Command::new(&binary_path)
                .arg(file)
                .arg(null_device())
                .output()
                .with_context(|| format!("failed to invoke yara for {}", file.display()))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("could not open file") && !stderr.contains("No such file") {
                    bail!("YARA rule error in {}: {}", file.display(), stderr.trim());
                }
            }
        }

        Ok((
            Self {
                rules_path: path.to_path_buf(),
                binary_path,
            },
            files.len(),
        ))
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>> {
        let files = collect_rule_files(&self.rules_path)?;
        let mut matches = Vec::new();

        for rule_file in files {
            let output = Command::new(&self.binary_path)
                .arg("-s")
                .arg("-w")
                .arg(&rule_file)
                .arg(path)
                .output()
                .with_context(|| {
                    format!(
                        "failed to invoke yara for rule {} against {}",
                        rule_file.display(),
                        path.display()
                    )
                })?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if !output.status.success() && stdout.trim().is_empty() && !stderr.trim().is_empty() {
                bail!("yara error: {}", stderr.trim());
            }

            if stdout.trim().is_empty() {
                continue;
            }

            let namespace = rule_file
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("default")
                .to_string();
            matches.extend(parse_yara_output(&stdout, &namespace));
        }

        Ok(matches)
    }
}

fn find_yara_binary() -> Result<PathBuf> {
    let binary = binary_name("yara");
    let mut searched = Vec::new();

    if let Some(path_var) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path_var) {
            let candidate = directory.join(&binary);
            searched.push(candidate.clone());
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    for candidate in fallback_yara_locations() {
        searched.push(candidate.clone());
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    let searched = searched
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("yara binary not found. Checked PATH and common install locations: {searched}")
}

fn binary_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn fallback_yara_locations() -> Vec<PathBuf> {
    let mut locations = Vec::new();

    if cfg!(target_os = "macos") {
        locations.push(PathBuf::from("/opt/homebrew/bin").join(binary_name("yara")));
        locations.push(PathBuf::from("/usr/local/bin").join(binary_name("yara")));
    }

    if cfg!(target_os = "linux") {
        locations.push(PathBuf::from("/usr/bin").join(binary_name("yara")));
        locations.push(PathBuf::from("/usr/local/bin").join(binary_name("yara")));
    }

    if cfg!(target_os = "windows") {
        locations.push(PathBuf::from(r"C:\Program Files\YARA").join(binary_name("yara")));
        locations.push(PathBuf::from(r"C:\Program Files (x86)\YARA").join(binary_name("yara")));
    }

    locations
}

fn null_device() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

fn collect_rule_files(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("could not access {}", path.display()))?;

    if metadata.is_file() {
        if has_rule_extension(path) {
            return Ok(vec![path.to_path_buf()]);
        }
        bail!("rules file must end with .yar or .yara");
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() && has_rule_extension(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }

    Ok(files)
}

fn has_rule_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "yar" | "yara"))
        .unwrap_or(false)
}

fn parse_yara_output(output: &str, namespace: &str) -> Vec<YaraMatch> {
    let mut matches: Vec<YaraMatch> = Vec::new();
    let mut current: Option<usize> = None;

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with("0x") {
            let Some(index) = current else {
                continue;
            };
            if let Some(matched_string) = parse_match_string(line) {
                matches[index].strings.push(matched_string);
            }
            continue;
        }

        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let rule_name = parts[0].to_string();
        let tags = if parts.len() >= 3 && parts[1].starts_with('[') && parts[1].ends_with(']') {
            parts[1]
                .trim_matches(['[', ']'])
                .split(',')
                .filter(|tag| !tag.trim().is_empty())
                .map(|tag| tag.trim().to_string())
                .collect()
        } else {
            Vec::new()
        };

        matches.push(YaraMatch {
            rule_name,
            namespace: namespace.to_string(),
            tags,
            strings: Vec::new(),
        });
        current = Some(matches.len() - 1);
    }

    matches
}

fn parse_match_string(line: &str) -> Option<YaraMatchString> {
    let (offset_hex, rest) = line.strip_prefix("0x")?.split_once(':')?;
    let (name, data) = rest.split_once(':')?;
    let offset = u64::from_str_radix(offset_hex, 16).ok()?;

    Some(YaraMatchString {
        name: name.trim().to_string(),
        offset,
        data: parse_match_data(data.trim()),
    })
}

fn parse_match_data(raw: &str) -> Vec<u8> {
    if raw.starts_with('{') && raw.ends_with('}') {
        let hex_data = raw
            .trim_matches(['{', '}'])
            .split_whitespace()
            .collect::<String>();
        if let Ok(bytes) = decode_hex(&hex_data) {
            return bytes;
        }
    }
    raw.as_bytes().to_vec()
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("hex data must have an even length");
    }

    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let part = std::str::from_utf8(&bytes[index..index + 2])?;
        let byte = u8::from_str_radix(part, 16)?;
        output.push(byte);
        index += 2;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{fallback_yara_locations, parse_match_data, parse_yara_output};

    #[test]
    fn parses_yara_rule_output() {
        let matches = parse_yara_output("wannacry sample.bin\n0x10:$a: WNcry@2017\n", "rule_list");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "wannacry");
        assert_eq!(matches[0].strings.len(), 1);
        assert_eq!(matches[0].strings[0].offset, 0x10);
    }

    #[test]
    fn decodes_hex_encoded_match_data() {
        assert_eq!(parse_match_data("{ 57 4e 63 72 79 }"), b"WNcry");
    }

    #[test]
    fn exposes_platform_fallback_locations() {
        if cfg!(target_os = "macos") {
            let locations = fallback_yara_locations();
            assert!(locations
                .iter()
                .any(|path| path == Path::new("/opt/homebrew/bin/yara")));
            assert!(locations
                .iter()
                .any(|path| path == Path::new("/usr/local/bin/yara")));
        }
    }
}
