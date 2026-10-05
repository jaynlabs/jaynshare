//! Token usage read from a relayed body without delaying it.

use serde_json::Value;

/// Bound on the copy kept for a non-streamed JSON body; larger bodies teach nothing.
const MAX_JSON_COPY: usize = 4 * 1024 * 1024;
/// Bound on one buffered SSE line; a longer line is not a usage event.
const MAX_SSE_LINE: usize = 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
}

#[derive(Debug)]
pub enum UsageExtractor {
    /// SSE: `message_start` carries input tokens, `message_delta` the
    /// cumulative output count; Codex's `response.completed` carries both.
    Stream { line: Vec<u8>, tokens: Tokens },
    /// A JSON body with a top-level `usage` object.
    Json { copy: Vec<u8> },
}

impl UsageExtractor {
    pub fn for_content_type(content_type: Option<&str>) -> Self {
        if content_type.is_some_and(|c| c.starts_with("text/event-stream")) {
            Self::Stream {
                line: Vec::new(),
                tokens: Tokens::default(),
            }
        } else {
            Self::Json { copy: Vec::new() }
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        match self {
            Self::Stream { line, tokens } => {
                for byte in chunk {
                    if *byte == b'\n' {
                        if let Some(data) = line.strip_prefix(b"data:") {
                            note_event(data, tokens);
                        }
                        line.clear();
                    } else if line.len() < MAX_SSE_LINE {
                        line.push(*byte);
                    }
                }
            }
            Self::Json { copy } => {
                if copy.len() + chunk.len() <= MAX_JSON_COPY {
                    copy.extend_from_slice(chunk);
                }
            }
        }
    }

    pub fn finish(self) -> Tokens {
        match self {
            Self::Stream { tokens, .. } => tokens,
            Self::Json { copy } => serde_json::from_slice::<Value>(&copy)
                .ok()
                .and_then(|v| usage_of(v.get("usage")?))
                .unwrap_or_default(),
        }
    }
}

fn note_event(data: &[u8], tokens: &mut Tokens) {
    let Ok(event) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    match event.get("type").and_then(Value::as_str) {
        Some("message_start") => {
            if let Some(u) = event
                .get("message")
                .and_then(|m| m.get("usage"))
                .and_then(usage_of)
            {
                tokens.input = u.input;
                tokens.output = tokens.output.max(u.output);
            }
        }
        Some("message_delta") => {
            if let Some(u) = event.get("usage").and_then(usage_of) {
                tokens.output = tokens.output.max(u.output);
            }
        }
        Some("response.completed") => {
            if let Some(u) = event
                .get("response")
                .and_then(|r| r.get("usage"))
                .and_then(usage_of)
            {
                *tokens = u;
            }
        }
        _ => {}
    }
}

fn usage_of(usage: &Value) -> Option<Tokens> {
    let number = |k: &str| usage.get(k).and_then(Value::as_u64).unwrap_or(0);
    usage.as_object()?;
    Some(Tokens {
        input: number("input_tokens"),
        output: number("output_tokens"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_usage_survives_chunk_splits() {
        let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":40}}\n\n";
        let mut x = UsageExtractor::for_content_type(Some("text/event-stream; charset=utf-8"));
        for chunk in sse.chunks(7) {
            x.feed(chunk);
        }
        assert_eq!(
            x.finish(),
            Tokens {
                input: 12,
                output: 40
            }
        );
    }

    #[test]
    fn codex_usage_comes_from_response_completed() {
        let sse = b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":7,\"total_tokens\":18}}}\n\n";
        let mut x = UsageExtractor::for_content_type(Some("text/event-stream"));
        x.feed(sse);
        assert_eq!(
            x.finish(),
            Tokens {
                input: 11,
                output: 7
            }
        );
    }

    #[test]
    fn json_usage_comes_from_the_top_level_object() {
        let mut x = UsageExtractor::for_content_type(Some("application/json"));
        x.feed(b"{\"id\":\"m\",\"usage\":{\"input_tokens\":3,\"output_tokens\":5}}");
        assert_eq!(
            x.finish(),
            Tokens {
                input: 3,
                output: 5
            }
        );
        let mut x = UsageExtractor::for_content_type(None);
        x.feed(b"{}");
        assert_eq!(x.finish(), Tokens::default());
    }
}
