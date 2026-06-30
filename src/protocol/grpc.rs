//! gRPC streaming-LLM passthrough adapter — Vertex AI / Bedrock streaming
//! services.
//!
//! The current gRPC adapters serve cloud-native LLM services: Vertex-GenAI
//! `endpoints/v1/publisher/google/models/anthropic.claude-3-opus-20240229:streamGenerateContent`,
//! AWS Bedrock `/model/{model_id}/invoke_streaming_with_response_stream`, and
//! Cohere gRPC. Each speaks HTTP/2 + protobuf over TLS.
//!
//! We don't ship a full protobuf schema (each provider has its own). The
//! practical response is:
//!
//!   - when a request to a known gRPC LLM provider arrives through the
//!     proxy, we forward it transparently without modifying the protobuf body;
//!   - the upstream's response stream is recognised as a 5-byte gRPC frame
//!     header followed by per-message protobuf bytes — we surface each
//!     protobuf message as [`Event::Raw`] so the inspector's regular
//!     expressions can still hot-match on ASCII text embedded inside the
//!     bytes (URLs, "curl | sh", "function_call" names, etc);
//!   - however because protobuf wire format mixes control bytes between
//!     ASCII words, the inspector may miss multi-token sequences (hence
//!     the regex match is best on token-of-interest text payload like JSON.
//!     introspection is best-effort only for gRPC today).
//!   - body-size limiting is enforced per-frame; refusal semantics for the
//!     proxy's block mode are the same SSE-equivalent: we short-circuit with
//!     a 200 OK `Content-Type: application/grpc` body containing a
//!     `code=PERMISSION_DENIED` status frame, which gRPC-aware clients
//!     translate into a normal `Status::code=7` failure.
//!
//! This is a *defensive-passthrough* adapter. For deeper inspection we
//! would need protobuf schemas; we don't ship those — we surface bytes so
//! the inspector can flag obvious ASCII-flag patterns like URLs / known
//! malicious strings.
//!
//! Wire shape (server-streaming gRPC frames):
//!
//! ```text
//!   compressed_flag (1 byte)  |
//!   length (4 bytes, big-endian) |
//!   message (length bytes)
//! ```
//!
//! Each frame is one protobuf-encoded response. We strip the 5-byte
//! header and send the message-body to the inspector via [`Event::Raw`].

use bytes::Bytes;
use futures_core::Stream;

use crate::protocol::{Event, ProtocolAdapter};

pub struct GrpcAdapter;

const NAME: &str = "grpc";
const BLOCK_STUB: &[u8] = b"\x00\x00\x00\x00\x02\x08\x07";

impl ProtocolAdapter for GrpcAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn accepts(&self, content_type: &str) -> bool {
        content_type.contains("application/grpc")
            || content_type.contains("grpc")
            || content_type.contains("proto")
    }

    fn inspect_body(&self, body: Bytes) -> Bytes {
        // Non-streaming gRPC response: pass through as-is. We do not
        // rewrite protobuf bytes. If block mode requires us to substitute,
        // the proxy will send `BLOCK_STUB` instead.
        body
    }

    fn stream(
        &self,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Event> + Send + 'static>> {
        use async_stream::stream;
        let body = body.clone();
        Box::pin(stream! {
            // Heuristic: a gRPC frame stream starts with compressed_flag
            // (0 or 1) followed by a 4-byte big-endian length. If the
            // very first byte is neither 0 nor 1, this isn't framed gRPC
            // — pass through the entire body as a single Raw event so
            // the inspector can still scan the bytes.
            if body.len() < 5 || (body[0] != 0 && body[0] != 1) {
                yield Event::Raw(body);
                return;
            }
            let mut cursor = 0;
            while cursor + 5 <= body.len() {
                let compressed = body[cursor];
                let len = u32::from_be_bytes([
                    body[cursor + 1],
                    body[cursor + 2],
                    body[cursor + 3],
                    body[cursor + 4],
                ]) as usize;
                cursor += 5;
                if compressed != 0 {
                    // We don't decompress gRPC frames in the MVP.
                    break;
                }
                if cursor + len > body.len() {
                    // Truncated frame — end of stream.
                    break;
                }
                yield Event::Raw(body.slice(cursor..cursor + len));
                cursor += len;
            }
        })
    }
}

/// Construct the gRPC-shaped response body that signals
/// `PERMISSION_DENIED` to a gRPC client. Clients surfacing this will
/// see `Status::code=7` (PermissionDenied) and surface the error as
/// their agent layer's `PermissionDeniedError`, which usually fails
/// the call rather than passing any extraneous data downstream.
///
/// Wire form:
/// ```text
///   compressed_flag = 0
///   length = 2
///   field 1 tag = 0x08 (Status.code)
///   varint = 7      (PERMISSION_DENIED)
/// ```
pub fn block_stub_body() -> Bytes {
    Bytes::from_static(BLOCK_STUB)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_stream::stream;
    use futures_util::StreamExt;

    #[test]
    fn recognizes_grpc_content_type() {
        let adapter = GrpcAdapter;
        assert!(adapter.accepts("application/grpc"));
        assert!(adapter.accepts("application/grpc+proto"));
        assert!(!adapter.accepts("text/event-stream"));
    }

    #[test]
    fn block_stub_body_is_two_byte_grpc_message() {
        let stub = block_stub_body();
        // 5 bytes header + payload.
        assert_eq!(stub.len(), 7);
        // compressed_flag = 0
        assert_eq!(stub[0], 0);
        // length = 2
        assert_eq!(u32::from_be_bytes([stub[1], stub[2], stub[3], stub[4]]), 2);
        // status.code tag = field 1, type varint = 0x08
        assert_eq!(stub[5], 0x08);
        // status value = PERMISSION_DENIED (7)
        assert_eq!(stub[6], 7);
    }

    #[test]
    fn stream_emits_each_grpc_frame_as_raw_event() {
        let adapter = GrpcAdapter;
        // Build two gRPC frames with payloads "AAAA" and "BBBB".
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x04]); // frame 1 header
        body.extend_from_slice(b"AAAA");
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x04]); // frame 2 header
        body.extend_from_slice(b"BBBB");
        let body = Bytes::from(body);

        let stream = adapter.stream(body);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events: Vec<Event> = runtime.block_on(async {
            stream.collect::<Vec<_>>().await
        });
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::Raw(ref b) if b.as_ref() == b"AAAA"));
        assert!(matches!(events[1], Event::Raw(ref b) if b.as_ref() == b"BBBB"));
    }

    #[test]
    fn stream_stops_on_truncated_frame() {
        let adapter = GrpcAdapter;
        // 5-byte header claims 4 bytes, but only 2 follow.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x04]);
        body.extend_from_slice(b"AB");
        let body = Bytes::from(body);
        let stream = adapter.stream(body);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events: Vec<Event> = runtime.block_on(async {
            stream.collect::<Vec<_>>().await
        });
        // No events emitted (state: header declared 4 bytes, only 2 available).
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn stream_drops_on_compressed_frame() {
        let adapter = GrpcAdapter;
        // First byte is compressed_flag = 1.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x04]);
        body.extend_from_slice(b"AAAA");
        let body = Bytes::from(body);
        let stream = adapter.stream(body);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events: Vec<Event> = runtime.block_on(async {
            stream.collect::<Vec<_>>().await
        });
        // Adapter bails on compressed frames — no events.
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn stream_passes_through_unrecognised_body() {
        let adapter = GrpcAdapter;
        let body = Bytes::from_static(b"hello without grpc framing");
        let stream = adapter.stream(body.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events: Vec<Event> = runtime.block_on(async {
            stream.collect::<Vec<_>>().await
        });
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::Raw(ref b) if b == &body));
    }

    // Silence unused-stream warning while still showing the import.
    // It's used above in the test bodies via async_stream.
    #[allow(dead_code)]
    fn _doc_clippy_workaround() {
        let _ = stream! {};
    }
}