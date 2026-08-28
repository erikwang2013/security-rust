// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

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
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::High, "WebSocket hijack attempt detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &WebSocketDetector,
            input,
            AttackCategory::Protocol,
            Severity::High,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&WebSocketDetector, input);
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
