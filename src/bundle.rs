//! Publish-ready certification bundle packaging.
//!
//! `cape certify` already emits the three core artifacts:
//! - `report.md`
//! - `badge.svg`
//! - `entry.json`
//!
//! `bundle.rs` turns that into something you can actually publish or hand to a
//! customer / provider:
//!
//! - deterministic file layout
//! - checksum manifest
//! - machine-readable bundle metadata
//! - one directory ready to zip/sign/upload

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::certify::RegistryEntry;
use crate::score::ProviderScore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetadata {
    pub schema_version: String,
    pub generated_at: String,
    pub host: String,
    pub upstream: String,
    pub grade: String,
    pub score: u32,
    pub files: Vec<BundleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

pub struct PublishBundle {
    pub metadata: BundleMetadata,
}

impl PublishBundle {
    pub fn write(
        out_dir: &Path,
        report: &ProviderScore,
        report_md: &str,
        badge_svg: &str,
        entry: &RegistryEntry,
    ) -> anyhow::Result<Self> {
        if !out_dir.exists() {
            std::fs::create_dir_all(out_dir)?;
        }

        let report_md_path = out_dir.join("report.md");
        let badge_svg_path = out_dir.join("badge.svg");
        let entry_json_path = out_dir.join("entry.json");

        std::fs::write(&report_md_path, report_md)?;
        std::fs::write(&badge_svg_path, badge_svg)?;
        std::fs::write(&entry_json_path, serde_json::to_string_pretty(entry)?)?;

        let files = vec![
            file_meta(&report_md_path, "report.md")?,
            file_meta(&badge_svg_path, "badge.svg")?,
            file_meta(&entry_json_path, "entry.json")?,
        ];

        let metadata = BundleMetadata {
            schema_version: "1".to_string(),
            generated_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            host: report.host.clone(),
            upstream: report.upstream.clone(),
            grade: format!("{:?}", report.grade),
            score: report.total,
            files,
        };

        let manifest = serde_json::to_string_pretty(&metadata)?;
        let manifest_path = out_dir.join("bundle.json");
        std::fs::write(&manifest_path, &manifest)?;
        let checksums_path = out_dir.join("SHA256SUMS");
        std::fs::write(&checksums_path, render_checksums(&metadata))?;

        Ok(Self { metadata })
    }
}

fn file_meta(path: &Path, label: &str) -> anyhow::Result<BundleFile> {
    let bytes = std::fs::read(path)?;
    let len = bytes.len() as u64;
    Ok(BundleFile {
        path: label.to_string(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes: len,
    })
}

fn render_checksums(metadata: &BundleMetadata) -> String {
    let mut out = String::new();
    for f in &metadata.files {
        out.push_str(&format!("{}  {}\n", f.sha256, f.path));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certify::RegistryEntry;
    use crate::scan::{RiskLevel, ScanReport};
    use crate::score::{render_badge_svg, render_markdown, score_provider};

    fn sample_score() -> ProviderScore {
        let scan = ScanReport {
            upstream: "https://api.deepseek.com".into(),
            protocol: "openai".into(),
            risk_score: 0,
            verdict: RiskLevel::Clean,
            categories: vec![],
            unsolicited_tool_uses: 0,
            bytes_received: 42,
            note: "clean".into(),
        };
        score_provider("https://api.deepseek.com", scan)
    }

    #[test]
    fn bundle_writes_expected_layout() {
        let score = sample_score();
        let badge = render_badge_svg(&score);
        let report_md = render_markdown(&score);
        let entry = RegistryEntry::from_score(&score, &badge);

        let dir = std::env::temp_dir().join(format!("carapace-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bundle = PublishBundle::write(&dir, &score, &report_md, &badge, &entry).unwrap();
        assert!(dir.join("report.md").exists());
        assert!(dir.join("badge.svg").exists());
        assert!(dir.join("entry.json").exists());
        assert!(dir.join("bundle.json").exists());
        assert!(dir.join("SHA256SUMS").exists());
        assert_eq!(bundle.metadata.files.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
