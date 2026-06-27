//! Protocol adapters — normalise provider-specific wire formats.
//!
//! holone's first architectural mistake was hardcoding Anthropic/OpenAI in the
//! proxy. We isolate the *protocol* from the *inspection*: each upstream
//! dialect implements [`ProtocolAdapter`], the inspector works on a single
//! [`Event`] enum, the proxy decides what to forward.
//!
//! MVP ships Anthropic + OpenAI. Future adapters (z.ai paas/v4, DeepSeek,
//! custom gateways) drop into this trait without touching the inspector.

use bytes::Bytes;

/// Normalised stream event produced by a protocol adapter.
///
/// Not serialised — `Raw` carries opaque bytes that we forward untouched.
#[derive(Debug, Clone)]
pub enum Event {
    /// A chunk of assistant text content.
    TextDelta(String),
    /// Announce a tool_use block with the given id/name (no input yet).
    ToolUseStart { id: String, name: String },
    /// A chunk of the tool's JSON input.
    ToolUseDelta(String),
    /// End of a tool_use block.
    ToolUseEnd,
    /// Raw passthrough chunk the adapter chose not to interpret.
    Raw(Bytes),
}

/// Per-upstream dialect.
pub trait ProtocolAdapter: Send + Sync {
    /// Identifier for logs (`anthropic`, `openai`, `zai`, …).
    fn name(&self) -> &'static str;

    /// Does this Content-Type look like ours?
    fn accepts(&self, content_type: &str) -> bool;

    /// Inspect (and possibly rewrite) a non-streaming response body before it
    /// reaches the client. Returns the bytes to forward.
    fn inspect_body(&self, body: Bytes) -> Bytes;

    /// Generator that turns a streaming `text/event-stream` into [`Event`]s.
    /// The proxy forwards the original bytes verbatim for_approved events
    /// and substitutes a safe stub for blocked ones.
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn futures_core::Stream<Item = Event> + Send + 'static>>;
}

/// Pick adapter by upstream URL / content-type. Returns the right adapter or
/// a fallback `PassthroughAdapter` that forwards bytes untouched.
pub fn pick(upstream: &str, content_type: &str) -> Box<dyn ProtocolAdapter> {
    if upstream.contains("anthropic.com") || content_type.contains("anthropic") {
        Box::new(AnthropicAdapter)
    } else if upstream.contains("openai.com")
        || content_type.contains("openai")
        || upstream.contains("/v1/")
    {
        Box::new(OpenAiAdapter)
    } else {
        Box::new(PassthroughAdapter)
    }
}

/// Anthropic Messages API (SSE: `message_start`, `content_block_delta`, …).
pub struct AnthropicAdapter;

/// OpenAI Chat Completions (SSE: `data: {choices:[{delta:{...}}]}`).
pub struct OpenAiAdapter;

/// Unknown protocol — forwards untouched. Detection engine still scans text.
pub struct PassthroughAdapter;

// The full adapters land in the next commit — for the first green build we wire
// the trait and use the passthrough adapter everywhere except anthropic.com.
impl ProtocolAdapter for PassthroughAdapter {
    fn name(&self) -> &'static str {
        "passthrough"
    }
    fn accepts(&self, _c: &str) -> bool {
        true
    }
    fn inspect_body(&self, body: Bytes) -> Bytes {
        body
    }
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn futures_core::Stream<Item = Event> + Send + 'static>> {
        use async_stream::stream;
        Box::pin(stream! { yield Event::Raw(body); })
    }
}

impl ProtocolAdapter for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }
    fn accepts(&self, c: &str) -> bool {
        c.contains("anthropic") || c.contains("event-stream")
    }
    fn inspect_body(&self, body: Bytes) -> Bytes {
        body
    }
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn futures_core::Stream<Item = Event> + Send + 'static>> {
        use async_stream::stream;
        Box::pin(stream! { yield Event::Raw(body); })
    }
}

impl ProtocolAdapter for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }
    fn accepts(&self, c: &str) -> bool {
        c.contains("openai") || c.contains("event-stream")
    }
    fn inspect_body(&self, body: Bytes) -> Bytes {
        body
    }
    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn futures_core::Stream<Item = Event> + Send + 'static>> {
        use async_stream::stream;
        Box::pin(stream! { yield Event::Raw(body); })
    }
}