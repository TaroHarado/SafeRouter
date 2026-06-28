//! Decoding the client's own declared tools so we can tell a legitimate
//! `Bash`/`Read`/`Write` call apart from an upstream-injected one.
//!
//! This is what holone calls "unsolicited tool_use" but it never wired up the
//! other half — it could only treat every tool_use as suspicious. carapace's
//! invariant is:
//!
//!   if a tool_use name is NOT in the client-declared list → high severity
//!   if it IS declared → still scan the input buffer (declared tools can still
//!                       be tricked into running malicious arguments)
//!
//! Format support:
//!
//! - Anthropic Messages API: request body has `tools: [{name: "Bash", ...}]`.
//! - OpenAI Chat Completions: request body has
//!   `tools: [{type: "function", function: {name: "get_weather"}}]`.

use std::collections::HashSet;

use bytes::Bytes;
use serde_json::Value;

/// Extract the set of tool names the client asked the upstream to use.
pub fn parse_request_tools(body: &Bytes, protocol: &str) -> HashSet<String> {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return HashSet::new(),
    };
    let tools = match value.get("tools").and_then(|t| t.as_array()) {
        Some(t) => t,
        None => return HashSet::new(),
    };
    let mut out = HashSet::with_capacity(tools.len());
    for t in tools {
        // Anthropic: {"name": "Bash", "description": ..., "input_schema": {...}}
        if let Some(name) = t.get("name").and_then(|v| v.as_str()) {
            out.insert(name.to_string());
            continue;
        }
        // OpenAI: {"type": "function", "function": {"name": "get_weather", ...}}
        if let Some(name) = t
            .pointer("/function/name")
            .and_then(|v| v.as_str())
        {
            out.insert(name.to_string());
        }
    }
    // Defensive: the protocol itself does not affect parsing — but log
    // it once for visibility.
    tracing::debug!(protocol, declared = out.len(), "parsed declared tools");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_anthropic_tools_array() {
        let body = Bytes::from(
            serde_json::json!({
                "model": "claude-3-5-sonnet-mock",
                "messages": [],
                "tools": [
                    {"name": "Bash", "description": "shell", "input_schema": {}},
                    {"name": "Read", "description": "read file", "input_schema": {}},
                    {"name": "Write", "description": "write file", "input_schema": {}}
                ]
            })
            .to_string(),
        );
        let tools = parse_request_tools(&body, "anthropic");
        assert!(tools.contains("Bash"));
        assert!(tools.contains("Read"));
        assert!(tools.contains("Write"));
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn parses_openai_tools_array() {
        let body = Bytes::from(
            serde_json::json!({
                "model": "gpt-4-mock",
                "messages": [],
                "tools": [
                    {"type": "function", "function": {"name": "get_weather"}},
                    {"type": "function", "function": {"name": "send_email"}}
                ]
            })
            .to_string(),
        );
        let tools = parse_request_tools(&body, "openai");
        assert!(tools.contains("get_weather"));
        assert!(tools.contains("send_email"));
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn no_tools_field_returns_empty_set() {
        let body = Bytes::from(
            serde_json::json!({"model": "x", "messages": []}).to_string(),
        );
        let tools = parse_request_tools(&body, "anthropic");
        assert!(tools.is_empty());
    }

    #[test]
    fn malformed_body_returns_empty_set() {
        let body = Bytes::from("not json at all");
        let tools = parse_request_tools(&body, "anthropic");
        assert!(tools.is_empty());
    }

    #[test]
    fn mixed_format_tools_all_extracted() {
        // Edge case — some upstreams accept both shapes. We want all of them.
        let body = Bytes::from(
            serde_json::json!({
                "tools": [
                    {"name": "Bash"},
                    {"type": "function", "function": {"name": "WebFetch"}}
                ]
            })
            .to_string(),
        );
        let tools = parse_request_tools(&body, "anthropic");
        assert_eq!(tools.len(), 2);
        assert!(tools.contains("Bash"));
        assert!(tools.contains("WebFetch"));
    }
}