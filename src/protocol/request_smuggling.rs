// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Transfer-Encoding:.*\r\n.*Transfer-Encoding:").unwrap(),
        Regex::new(r"(?i)Transfer-Encoding:[\s]*chunked").unwrap(),
    ]
});

pub struct RequestSmugglingDetector;

impl Detector for RequestSmugglingDetector {
    fn name(&self) -> &'static str {
        "request_smuggling"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "request_smuggling".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "HTTP request smuggling detected".into(),
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
        let r = RequestSmugglingDetector
            .detect(input)
            .expect("expected request_smuggling detection");
        assert_eq!(r.attack_type, "request_smuggling");
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
            RequestSmugglingDetector.detect(input).is_none(),
            "not detected: {input:?}"
        );
    }

    #[test]
    fn name_is_request_smuggling() {
        assert_eq!(RequestSmugglingDetector.name(), "request_smuggling");
    }

    #[test]
    fn detects_duplicate_transfer_encoding() {
        assert_detected("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity");
    }

    #[test]
    fn detects_chunked_transfer_encoding() {
        assert_detected("Transfer-Encoding: chunked");
        assert_detected("Transfer-Encoding:chunked");
        assert_detected("Transfer-Encoding:\tchunked");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("transfer-encoding: CHUNKED");
    }

    #[test]
    fn rejects_benign_headers() {
        assert_clean("Content-Length: 5\r\nContent-Length: 10");
        assert_clean("Transfer-Encoding: gzip");
        assert_clean("Connection: keep-alive");
    }

    #[test]
    fn rejects_missing_colon() {
        assert_clean("Transfer-Encoding chunked");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("Transfer-Encoding: chuncked");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("普通请求体，无攻击特征");
    }
}
