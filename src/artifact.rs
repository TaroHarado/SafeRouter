//! Verification for publish-ready bundles.
//!
//! This closes the loop on `cape certify`:
//! if you can emit `report.md + badge.svg + entry.json + bundle.json + SHA256SUMS`,
//! you also need to be able to locally verify that a bundle wasn't tampered
//! with before you trust or publish it.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::BundleMetadata;
use crate::certify::RegistryEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVerification {
    pub path: String,
    pub files_ok: bool,
    pub checksums_ok: bool,
    pub entry_signature_ok: Option<bool>,
    pub summary: String,
}

pub fn verify_bundle(dir: &Path, pubkey: Option<&str>) -> anyhow::Result<ArtifactVerification> {
    let bundle_path = dir.join("bundle.json");
    let sums_path = dir.join("SHA256SUMS");
    let entry_path = dir.join("entry.json");

    let bundle_raw = std::fs::read_to_string(&bundle_path)
        .with_context(|| format!("read {}", bundle_path.display()))?;
    let bundle: BundleMetadata = serde_json::from_str(&bundle_raw)
        .with_context(|| format!("parse {}", bundle_path.display()))?;

    let sums_raw = std::fs::read_to_string(&sums_path)
        .with_context(|| format!("read {}", sums_path.display()))?;
    let expected_sums = parse_sha256sums(&sums_raw)?;

    let mut files_ok = true;
    let mut checksums_ok = true;
    for file in &bundle.files {
        let path = dir.join(&file.path);
        if !path.exists() {
            files_ok = false;
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let got = hex::encode(Sha256::digest(&bytes));
        if got != file.sha256 {
            checksums_ok = false;
        }
        if let Some(sum) = expected_sums.get(&file.path) {
            if *sum != got {
                checksums_ok = false;
            }
        } else {
            checksums_ok = false;
        }
    }

    let entry_signature_ok = if let Some(pk) = pubkey {
        let raw = std::fs::read_to_string(&entry_path)
            .with_context(|| format!("read {}", entry_path.display()))?;
        let entry: RegistryEntry = serde_json::from_str(&raw)
            .with_context(|| format!("parse {}", entry_path.display()))?;
        Some(entry.verify_with_pubkey(pk).is_ok())
    } else {
        None
    };

    let summary = match (files_ok, checksums_ok, entry_signature_ok) {
        (true, true, Some(true)) => "bundle, checksums, and entry signature all verify".to_string(),
        (true, true, None) => "bundle and checksums verify; entry signature not checked".to_string(),
        (true, false, _) => "bundle files exist but checksums mismatch".to_string(),
        (false, _, _) => "bundle is incomplete or missing files".to_string(),
        _ => "bundle verification failed".to_string(),
    };

    Ok(ArtifactVerification {
        path: dir.display().to_string(),
        files_ok,
        checksums_ok,
        entry_signature_ok,
        summary,
    })
}

fn parse_sha256sums(raw: &str) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let sum = parts.next().context("missing checksum")?;
        let file = parts.next().context("missing path")?;
        map.insert(file.to_string(), sum.to_string());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::PublishBundle;
    use crate::certify::RegistryEntry;
    use crate::scan::{RiskLevel, ScanReport};
    use crate::score::{render_badge_svg, render_markdown, score_provider};

    #[test]
    fn verify_bundle_round_trip() {
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
        let score = score_provider("https://api.deepseek.com", scan);
        let badge = render_badge_svg(&score);
        let report_md = render_markdown(&score);
        let entry = RegistryEntry::from_score(&score, &badge);

        let dir = std::env::temp_dir().join(format!("carapace-artifact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        PublishBundle::write(&dir, &score, &report_md, &badge, &entry).unwrap();

        let verification = verify_bundle(&dir, None).unwrap();
        assert!(verification.files_ok);
        assert!(verification.checksums_ok);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
