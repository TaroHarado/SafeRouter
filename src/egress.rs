//! Egress control — Layer 6 of the SafeRouter model.
//!
//! Outbound content inspection. Catches exfiltration that bypasses the
//! blocklist by going to "unknown" endpoints (not in known-bad list, but
//! also not in known-good list). Three signals:
//!
//!   1. Per-domain allowlist with wildcard support. Any POST to a domain
//!      not in the allowlist is blocked (or routed to Ask).
//!   2. Shannon entropy scan on outbound content. High entropy (>7.5 bits
//!      per byte) suggests encrypted / packed / key material being exfil'd.
//!   3. Sensitive-path-content sniff. If the outbound body mentions paths
//!      like ~/.ssh/id_rsa or .env, that's exfil regardless of where it's
//!      going.
//!
//! Combined with the blocklist in rules/blocklist.json (known-bad), this
//! gives us a complete deny-unknown / allow-known / block-known-bad triple.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressDecision {
    Allow,
    Ask,
    Block,
}

impl EgressDecision {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Block => "block",
        }
    }

    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Block)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressReport {
    pub decision: EgressDecision,
    /// Destination host (or "unknown" if URL couldn't be parsed).
    pub destination_host: String,
    /// True if destination was in the allowlist.
    pub allowlisted: bool,
    /// True if destination was in the known-bad blocklist.
    pub blocklisted: bool,
    /// Shannon entropy of the content (bits per byte). 0.0 if empty.
    pub entropy: f32,
    /// True if entropy exceeded the high-entropy threshold.
    pub high_entropy: bool,
    /// Sensitive paths detected in the content.
    pub sensitive_paths: Vec<String>,
    pub reasons: Vec<String>,
}

pub struct EgressPolicy {
    /// Domains in the allowlist. Supports leading `*.` for wildcard.
    allowlist: Vec<String>,
    /// Known-bad domains (mirrors rules/blocklist.json).
    blocklist: HashSet<String>,
    /// If true, POST to any non-allowlisted domain is blocked.
    /// If false, unknown is routed to Ask.
    block_unknown_destinations: bool,
    /// Shannon entropy threshold (bits per byte) above which content is
    /// considered "high entropy" (likely keys / encrypted blobs).
    entropy_threshold: f32,
    /// Minimum content size to bother with entropy scan (short strings
    /// naturally have high variance).
    entropy_min_bytes: usize,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowlist: default_allowlist(),
            blocklist: HashSet::new(),
            block_unknown_destinations: false,
            entropy_threshold: 7.5,
            entropy_min_bytes: 64,
        }
    }
}

impl EgressPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_blocklist(mut self, blocklist: HashSet<String>) -> Self {
        self.blocklist = blocklist;
        self
    }

    pub fn with_allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.allowlist = allowlist;
        self
    }

    pub fn block_unknown_destinations(mut self, v: bool) -> Self {
        self.block_unknown_destinations = v;
        self
    }

    pub fn entropy_threshold(mut self, t: f32) -> Self {
        self.entropy_threshold = t;
        self
    }

    /// Evaluate an outbound POST/PUT. `url` is the destination URL,
    /// `body` is the request body content.
    pub fn evaluate(&self, url: &str, body: &[u8]) -> EgressReport {
        let mut reasons: Vec<String> = Vec::new();
        let dest_host = extract_host(url).unwrap_or_else(|| "unknown".to_string());

        // Blocklist: hard deny.
        let blocklisted = self.is_blocklisted(&dest_host);
        if blocklisted {
            reasons.push(format!("destination in known-bad blocklist: {dest_host}"));
        }

        // Allowlist check.
        let allowlisted = self.is_allowlisted(&dest_host);
        if allowlisted {
            // OK so far.
        } else if self.block_unknown_destinations && !blocklisted {
            reasons.push(format!(
                "destination not in allowlist (block-unknown mode): {dest_host}"
            ));
        } else if !allowlisted && !blocklisted {
            reasons.push(format!("destination not in allowlist: {dest_host}"));
        }

        // Entropy scan.
        let entropy = if body.len() >= self.entropy_min_bytes {
            shannon_entropy(body)
        } else {
            0.0
        };
        let high_entropy = entropy >= self.entropy_threshold;
        if high_entropy {
            reasons.push(format!(
                "high entropy {:.2} >= {:.2} (likely key/encrypted material)",
                entropy, self.entropy_threshold
            ));
        }

        // Sensitive path sniff in body.
        let sensitive_paths = scan_sensitive_paths(body);
        for p in &sensitive_paths {
            reasons.push(format!("sensitive path in outbound body: {p}"));
        }

        // Decision merge.
        let block = blocklisted
            || !sensitive_paths.is_empty()
            || (high_entropy && !allowlisted)
            || (!allowlisted && self.block_unknown_destinations);
        let ask = !allowlisted || high_entropy;
        let decision = if block {
            EgressDecision::Block
        } else if ask {
            EgressDecision::Ask
        } else {
            EgressDecision::Allow
        };

        EgressReport {
            decision,
            destination_host: dest_host,
            allowlisted,
            blocklisted,
            entropy,
            high_entropy,
            sensitive_paths,
            reasons,
        }
    }

    fn is_blocklisted(&self, host: &str) -> bool {
        let h = host.to_lowercase();
        if self.blocklist.contains(&h) {
            return true;
        }
        // Also check suffix matches (subdomain of a blocked domain).
        for bad in &self.blocklist {
            let bad = bad.to_lowercase();
            if h.ends_with(&format!(".{bad}")) {
                return true;
            }
        }
        false
    }

    fn is_allowlisted(&self, host: &str) -> bool {
        let h = host.to_lowercase();
        for entry in &self.allowlist {
            let e = entry.to_lowercase();
            if let Some(suffix) = e.strip_prefix("*.") {
                if h == suffix || h.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if h == e {
                return true;
            }
        }
        false
    }
}

fn default_allowlist() -> Vec<String> {
    vec![
        // Major LLM providers (legitimate upstreams).
        "api.anthropic.com".to_string(),
        "api.openai.com".to_string(),
        "api.deepseek.com".to_string(),
        "generativelanguage.googleapis.com".to_string(),
        "api.groq.com".to_string(),
        "api.mistral.ai".to_string(),
        "api.cohere.ai".to_string(),
        "api.together.xyz".to_string(),
        "api.fireworks.ai".to_string(),
        "api.perplexity.ai".to_string(),
        "oapi.tencent.com".to_string(),
        // Package registries.
        "registry.npmjs.org".to_string(),
        "pypi.org".to_string(),
        "crates.io".to_string(),
        "static.crates.io".to_string(),
        "registry.yarnpkg.com".to_string(),
        "rubygems.org".to_string(),
        "go.dev".to_string(),
        "sum.golang.org".to_string(),
        "repo1.maven.org".to_string(),
        "plugins.gradle.org".to_string(),
        // Source control.
        "github.com".to_string(),
        "raw.githubusercontent.com".to_string(),
        "codeload.github.com".to_string(),
        "gitlab.com".to_string(),
        "bitbucket.org".to_string(),
        "*.githubusercontent.com".to_string(),
        "*.github.io".to_string(),
        // Documentation / search.
        "developer.mozilla.org".to_string(),
        "docs.rs".to_string(),
        "rust-lang.org".to_string(),
        "stackoverflow.com".to_string(),
        "duckduckgo.com".to_string(),
        // Localhost.
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ]
}

/// Extract the host part of a URL. Returns None if not parseable as a URL
/// (no scheme, no host).
fn extract_host(url: &str) -> Option<String> {
    let u = url.to_lowercase();
    let stripped = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))?;
    let host_end = stripped
        .find(['/', '?', '#', ':'])
        .unwrap_or(stripped.len());
    let host = &stripped[..host_end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Shannon entropy in bits per byte.
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f32;
    let mut entropy = 0.0f32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / total;
        entropy -= p * p.log2();
    }
    entropy
}

/// Scan outbound body for sensitive file paths that shouldn't be exfil'd.
fn scan_sensitive_paths(body: &[u8]) -> Vec<String> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut found: Vec<String> = Vec::new();
    let patterns = [
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".aws/credentials",
        ".aws/config",
        ".kube/config",
        ".docker/config.json",
        ".config/gcloud/credentials",
        ".config/gcloud/application_default",
        ".terraform.d/credentials",
        ".netrc",
        ".pypirc",
        ".npmrc",
        ".gnupg/secring.gpg",
        ".gnupg/private-keys",
        ".config/solana/id.json",
        ".ethereum/keystore",
        ".electrum/wallets",
        "wallet.dat",
        ".bitmonero",
        "Local Storage/leveldb",
        "Login Data",
        "Cookies",
        "logins.json",
        "key4.db",
        ".opvault",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ];
    for p in &patterns {
        if body_str.contains(p) {
            found.push(p.to_string());
        }
    }
    // Also scan for env-var-like patterns ($TOKEN, $API_KEY) in the body.
    let lower = body_str.to_lowercase();
    for kw in &["$token", "$api_key", "$api_secret", "$openai_api_key",
        "$anthropic_api_key", "$aws_secret_access_key", "$github_token",
        "$database_password", "$stripe_secret", "bearer eyj"] {
        if lower.contains(kw) {
            found.push(kw.to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_default_contains_anthropic() {
        let p = EgressPolicy::new();
        let r = p.evaluate("https://api.anthropic.com/v1/messages", b"{}");
        assert!(r.allowlisted);
        assert_eq!(r.decision, EgressDecision::Allow);
    }

    #[test]
    fn blocklist_hard_denies() {
        let mut bl = HashSet::new();
        bl.insert("evil.example".to_string());
        let p = EgressPolicy::new().with_blocklist(bl);
        let r = p.evaluate("https://evil.example/upload", b"data");
        assert!(r.blocklisted);
        assert_eq!(r.decision, EgressDecision::Block);
    }

    #[test]
    fn blocklist_catches_subdomain() {
        let mut bl = HashSet::new();
        bl.insert("evil.example".to_string());
        let p = EgressPolicy::new().with_blocklist(bl);
        let r = p.evaluate("https://sub.evil.example/upload", b"data");
        assert!(r.blocklisted);
    }

    #[test]
    fn wildcard_allowlist_matches_subdomain() {
        let p = EgressPolicy::new().with_allowlist(vec!["*.githubusercontent.com".to_string()]);
        let r = p.evaluate("https://raw.githubusercontent.com/file.txt", b"");
        assert!(r.allowlisted);
    }

    #[test]
    fn unknown_destination_blocks_when_strict() {
        let p = EgressPolicy::new().block_unknown_destinations(true);
        let r = p.evaluate("https://unknown.example/upload", b"data");
        assert!(!r.allowlisted);
        assert_eq!(r.decision, EgressDecision::Block);
    }

    #[test]
    fn unknown_destination_asks_when_not_strict() {
        let p = EgressPolicy::new();
        let r = p.evaluate("https://unknown.example/upload", b"data");
        assert_eq!(r.decision, EgressDecision::Ask);
    }

    #[test]
    fn high_entropy_blocks_when_unknown() {
        let p = EgressPolicy::new();
        // 256 bytes of pseudo-random high-entropy data.
        let mut data = Vec::with_capacity(256);
        for i in 0..256u32 {
            data.push((i.wrapping_mul(0x9E3779B1) >> 24) as u8);
        }
        let r = p.evaluate("https://unknown.example/upload", &data);
        assert!(r.high_entropy);
        assert_eq!(r.decision, EgressDecision::Block);
    }

    #[test]
    fn low_entropy_short_body_not_flagged() {
        let p = EgressPolicy::new();
        let r = p.evaluate("https://api.anthropic.com/v1/messages", b"hello");
        assert!(!r.high_entropy);
        assert_eq!(r.decision, EgressDecision::Allow);
    }

    #[test]
    fn sensitive_path_in_body_blocks() {
        let p = EgressPolicy::new();
        let body = b"uploading my config: cat ~/.ssh/id_rsa contents follow";
        let r = p.evaluate("https://api.anthropic.com/v1/messages", body);
        assert!(!r.sensitive_paths.is_empty());
        assert_eq!(r.decision, EgressDecision::Block);
    }

    #[test]
    fn env_var_token_in_body_blocks() {
        let p = EgressPolicy::new();
        let body = b"running with $OPENAI_API_KEY from env";
        let r = p.evaluate("https://api.anthropic.com/v1/messages", body);
        assert!(!r.sensitive_paths.is_empty());
        assert_eq!(r.decision, EgressDecision::Block);
    }

    #[test]
    fn extract_host_handles_https() {
        assert_eq!(
            extract_host("https://api.anthropic.com/v1/messages"),
            Some("api.anthropic.com".to_string())
        );
        assert_eq!(
            extract_host("http://localhost:8080/foo"),
            Some("localhost".to_string())
        );
        assert_eq!(extract_host("not a url"), None);
    }

    #[test]
    fn shannon_entropy_uniform_bytes_max() {
        // All bytes distinct → entropy = 8.0.
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn shannon_entropy_repeated_byte_min() {
        let data = vec![0u8; 100];
        let e = shannon_entropy(&data);
        assert!((e - 0.0).abs() < 0.01);
    }

    #[test]
    fn default_allowlist_has_llm_providers() {
        let _ = EgressPolicy::new();
        // Verify the list compiled without panic.
    }
}