// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Upgrade:\s*websocket").unwrap(),
        Regex::new(r"(?i)Sec-WebSocket-Key:").unwrap(),
        Regex::new(r"(?i)Origin:\s*null.*Upgrade").unwrap(),
        Regex::new(r"(?i)ws://").unwrap(),
    ]
});

pub struct WebSocketDetector;

impl Detector for WebSocketDetector {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "websocket".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "WebSocket hijack attempt detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        let r = WebSocketDetector
            .detect(input)
            .expect("expected websocket detection");
        assert_eq!(r.attack_type, "websocket");
        assert_eq!(r.category, AttackCategory::Protocol);
        assert_eq!(r.severity, Severity::High);
        assert!(!r.matched_pattern.is_empty());
        assert!(r.offset <= input.len());
        assert_eq!(
            &input[r.offset..r.offset + r.matched_pattern.len()],
            r.matched_pattern
        );
        assert!(!r.message.is_empty());
    }

    fn assert_clean(input: &str) {
        assert!(
            WebSocketDetector.detect(input).is_none(),
            "not detected: {input:?}"
        );
    }

    #[test]
    fn name_is_websocket() {
        assert_eq!(WebSocketDetector.name(), "websocket");
    }

    #[test]
    fn detects_upgrade_header() {
        assert_detected("Upgrade: websocket");
    }

    #[test]
    fn detects_sec_websocket_key() {
        assert_detected("Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
    }

    #[test]
    fn detects_ws_scheme() {
        assert_detected("ws://evil.com/socket");
    }

    #[test]
    fn detects_null_origin_upgrade() {
        assert_detected("Origin: null Upgrade: websocket");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("upgrade: WebSocket");
        assert_detected("SEC-WEBSOCKET-KEY: abc==");
    }

    #[test]
    fn rejects_benign_requests() {
        assert_clean("Upgrade: h2c");
        assert_clean("Sec-WebSocket-Protocol: chat");
        assert_clean("wss://example.com/socket");
        assert_clean("Origin: https://example.com");
        assert_clean("GET /chat HTTP/1.1\r\nConnection: keep-alive");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("WebSocket 握手信息");
    }
}
