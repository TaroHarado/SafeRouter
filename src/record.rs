//! Forensics recorder — append-only JSONL of every verdict.
//!
//! This is the *first* layer of a full record/replay subsystem; later commits
//! will encrypt the file and rotate it. Right now we append a single line per
//! verdict so the user can `tail -f` the file or pipe to `jq`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use time::OffsetDateTime;

use crate::inspect::Verdict;
use crate::protocol::Event;

#[derive(Serialize)]
pub struct LogEntry {
    pub ts: String,
    pub protocol: String,
    pub mode: String,
    pub severity: u32,
    pub categories: String,
    pub tool_name: Option<String>,
    pub unsolicited_tool_use: bool,
    pub snippet: String,
}

pub struct Recorder {
    file: Mutex<Option<std::fs::File>>,
    sink_stderr: bool,
}

impl Recorder {
    /// Open log file at `path`, or `-` for stderr.
    pub fn open(path: &str) -> std::io::Result<Self> {
        let (file, sink_stderr) = if path == "-" {
            (None, true)
        } else {
            let p = PathBuf::from(path);
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let f = OpenOptions::new().create(true).append(true).open(&p)?;
            (Some(f), false)
        };
        Ok(Self {
            file: Mutex::new(file),
            sink_stderr,
        })
    }

    pub fn record(
        &self,
        protocol: &str,
        mode: &str,
        verdict: &Verdict,
        buffer: &str,
    ) -> std::io::Result<()> {
        let entry = LogEntry {
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            protocol: protocol.to_string(),
            mode: mode.to_string(),
            severity: verdict.severity,
            categories: verdict.categories(),
            tool_name: verdict.tool_name.clone(),
            unsolicited_tool_use: verdict.unsolicited_tool_use,
            snippet: truncate(buffer, 512),
        };
        let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string());
        if self.sink_stderr {
            eprintln!("{line}");
        } else if let Some(f) = self.file.lock().unwrap().as_mut() {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }

    /// Convenience: record a passthrough event without a verdict (for `scan`).
    pub fn note(&self, protocol: &str, message: &str) -> std::io::Result<()> {
        let entry = LogEntry {
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            protocol: protocol.to_string(),
            mode: "scan".to_string(),
            severity: 0,
            categories: message.to_string(),
            tool_name: None,
            unsolicited_tool_use: false,
            snippet: String::new(),
        };
        let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string());
        if self.sink_stderr {
            eprintln!("{line}");
        } else if let Some(f) = self.file.lock().unwrap().as_mut() {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }

    /// Append a raw event for replay-mode (later). Stubbed for the first build.
    pub fn raw_event(&self, _event: &Event) -> std::io::Result<()> {
        Ok(())
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut t = s[..n].to_string();
        t.push('…');
        t
    }
}