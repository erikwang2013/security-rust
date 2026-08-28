// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

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
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::High, "HTTP request smuggling detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &RequestSmugglingDetector,
            input,
            AttackCategory::Protocol,
            Severity::High,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&RequestSmugglingDetector, input);
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
