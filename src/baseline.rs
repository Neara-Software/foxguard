use crate::Finding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    pub version: u32,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

impl BaselineFile {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries = findings.iter().map(BaselineEntry::from_finding).collect();
        Self {
            version: 1,
            entries,
        }
    }
}

impl BaselineEntry {
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            fingerprint: fingerprint_finding(finding),
            rule_id: finding.rule_id.clone(),
            file: finding.file.clone(),
            line: finding.line,
            snippet: finding.snippet.clone(),
        }
    }
}

pub fn fingerprint_finding(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(finding.file.as_bytes());
    hasher.update([0]);
    hasher.update(finding.snippet.as_bytes());
    hasher.update([0]);
    hasher.update(finding.line.to_string().as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn load_baseline(path: &Path) -> Result<Option<BaselineFile>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read baseline {}: {}", path.display(), e))?;
    let baseline = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse baseline {}: {}", path.display(), e))?;
    Ok(Some(baseline))
}

pub fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create baseline directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }

    let baseline = BaselineFile::from_findings(findings);
    let content = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("Failed to serialize baseline: {}", e))?;
    std::fs::write(path, content)
        .map_err(|e| format!("Failed to write baseline {}: {}", path.display(), e))
}

pub fn suppress_with_baseline(
    findings: Vec<Finding>,
    baseline: Option<&BaselineFile>,
) -> Vec<Finding> {
    let Some(baseline) = baseline else {
        return findings;
    };

    findings
        .into_iter()
        .filter(|finding| {
            let fingerprint = fingerprint_finding(finding);
            !baseline
                .entries
                .iter()
                .any(|entry| entry.fingerprint == fingerprint)
        })
        .collect()
}
