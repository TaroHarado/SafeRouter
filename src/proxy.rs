//! Inspecting reverse proxy.
//!
//! Sits between an AI client (Claude Code, Cline, Cursor, Aider…) and an
//! upstream LLM provider. Forwards requests verbatim, reads responses through
//! the streaming reassembly pipeline, and either logs alerts or substitutes a
//! safe stub for malicious tool_use chunks before the client sees them.
//!
//! MVP note for the first commit: response bodies are buffered fully before
//! inspection — this is *correct* for chunked-injection defence (the whole
//! point of "reassemble before scan") but trades latency. The real
//! incremental-streaming housekeeping arrives in the next commit; the buffer
//! strategy here is the load-bearing safety property.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, BodyStream, Full};
use hyper::body::Body;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::cli::Mode;
use crate::inspect::{Inspector, Verdict};
use crate::protocol::{self, Event, ProtocolAdapter};
use crate::record::Recorder;
use crate::secure::Secret;

pub struct ProxyConfig {
    pub upstream: String,
    pub listen: SocketAddr,
    pub upstream_key: Secret,
    pub mode: Mode,
    pub recorder: Arc<Recorder>,
}

/// Entry point — runs until Ctrl-C.
pub async fn run(cfg: ProxyConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen=%cfg.listen, upstream=%cfg.upstream, mode=?cfg.mode, "carapace proxy up");

    let upstream = Arc::new(cfg.upstream.clone());
    let key = Arc::new(cfg.upstream_key);
    let mode = cfg.mode;
    let recorder = cfg.recorder.clone();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error=%e, "accept failure");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let upstream = upstream.clone();
        let key = key.clone();
        let recorder = recorder.clone();
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| {
                    let upstream = upstream.clone();
                    let key = key.clone();
                    let recorder = recorder.clone();
                    async move { forward(req, &upstream, &key, mode, &recorder).await }
                }))
                .with_upgrades()
                .await
            {
                tracing::debug!(error=%e, ?peer, "connection ended");
            }
        });
    }
}

async fn forward(
    req: Request<hyper::body::Incoming>,
    upstream: &str,
    key: &Secret,
    mode: Mode,
    recorder: &Recorder,
) -> anyhow::Result<Response<BoxBody>> {
    let (mut parts, body) = req.into_parts();

    // Build the upstream URI. If the user supplied an absolute URL we keep it;
    // otherwise concatenate upstream + original path/query.
    let upstream_uri = if parts.uri.scheme().is_some() {
        parts.uri.clone()
    } else {
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let base = upstream.trim_end_matches('/');
        Uri::try_from(format!("{base}{path}"))?
    };

    // Body — fully read for small request bodies; for streaming uploads we
    // currently fall back to forwarding the buffered bytes (good enough for
    // Anthropic/OpenAI Chat Completions which are small JSON).
    let body_bytes = body.collect().await?.to_bytes();
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let adapter = protocol::pick(upstream, &content_type);
    let protocol_name = adapter.name();

    // Build the outbound request.
    parts.uri = upstream_uri;
    if !key.is_empty() {
        // Anthropic uses x-api-key; OpenAI uses Authorization Bearer. We send
        // both — the receiving side will pick what it knows.
        if protocol_name == "anthropic" {
            parts
                .headers
                .insert("x-api-key", key.as_str().parse()?);
        } else {
            let auth = format!("Bearer {}", key.as_str());
            parts.headers.insert(http::header::AUTHORIZATION, auth.parse()?);
        }
    }
    // Strip Host header — the client will supply its own.
    parts.headers.remove(http::header::HOST);

    let out_req: Request<Full<Bytes>> = match parts.method {
        Method::GET | Method::HEAD => Request::from_parts(parts, Full::default()),
        _ => Request::from_parts(parts, Full::new(body_bytes.clone())),
    };

    // Connect upstream via TokioIo.
    let upstream_host = extract_host(upstream);
    let stream = tokio::net::TcpStream::connect(&upstream_host).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let upstream_resp = sender.send_request(out_req).await?;
    let (rparts, rbody) = upstream_resp.into_parts();

    // NOTE: For the first commit we buffer the whole response body. The next
    // commit will stream chunks through the adapter and only buffer when a
    // tool_use is detected.
    let resp_bytes = rbody.collect().await?.to_bytes();
    let _ = Body::size_hint(&Full::<Bytes>::default());

    let allowed_tools = parse_declared_tools(&body_bytes, protocol_name);
    let mut inspector = Inspector::builtin(allowed_tools);
    let verdict = inspector.feed(&Event::Raw(resp_bytes.clone()));

    let final_body = if !verdict.is_clean() && matches!(mode, Mode::Block) && verdict.severity >= 60
    {
        substitute_with_stub(&rparts.status, &rparts.headers, protocol_name)
    } else {
        resp_bytes
    };

    let _ = recorder.record(protocol_name, mode_label(mode), &verdict, inspector.last_buffer());

    // Rebuild the response from parts + final body.
    let mut resp = Response::from_parts(rparts, full(final_body));
    if resp.status() == StatusCode::default() {
        *resp.status_mut() = StatusCode::OK;
    }
    Ok(resp)
}

fn extract_host(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    trimmed_host(stripped).to_string()
}

fn trimmed_host(s: &str) -> &str {
    s.split('/').next().unwrap_or(s)
}

fn mode_label(m: Mode) -> &'static str {
    match m {
        Mode::Monitor => "monitor",
        Mode::Block => "block",
    }
}

/// Parse `tools` array from the request body to know which tool_use the client
/// actually declared. Anything else is treated as unsolicited by the inspector.
fn parse_declared_tools(_body: &Bytes, _protocol: &str) -> std::collections::HashSet<String> {
    // Lightweight parse: look for `"name":"..."` inside the `tools` array.
    // Full schema-aware version arrives next commit. Returning an empty set
    // for now makes any tool_use from upstream unsolicited — safer default.
    std::collections::HashSet::new()
}

impl Inspector {
    fn last_buffer(&self) -> &str {
        // The inspector keeps the most recent buffer; for the recorder snippet.
        // Accessor not exposed publicly — for now return the empty string if
        // the buffer is gone.
        ""
    }
}

fn substitute_with_stub(
    _status: &StatusCode,
    _headers: &http::HeaderMap,
    protocol: &str,
) -> Bytes {
    let stub = match protocol {
        "anthropic" => serde_json::json!({
            "type": "error",
            "error": {
                "type": "blocked_by_carapace",
                "message": "Response contained a high-severity injection and was replaced by carapace."
            }
        })
        .to_string(),
        _ => serde_json::json!({
            "error": {
                "message": "Response contained a high-severity injection and was replaced by carapace.",
                "type": "blocked_by_carapace"
            }
        })
        .to_string(),
    };
    Bytes::from(stub)
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

fn full(b: Bytes) -> BoxBody {
    let body = Full::new(b).map_err(|e| match e {}).boxed();
    body
}

// Silence unused import warnings while streaming inspection lands in next commit.
#[allow(dead_code)]
fn _use_stream() -> BodyStream<Full<Bytes>> {
    unimplemented!()
}