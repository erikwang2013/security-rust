// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Origin:\s*null").unwrap(),
        Regex::new(r"(?i)Access-Control-Allow-Origin:\s*\*").unwrap(),
        Regex::new(r"(?i)Access-Control-Allow-Credentials:\s*true").unwrap(),
    ]
});

pub struct CorsDetector;

impl Detector for CorsDetector {
    fn name(&self) -> &'static str {
        "cors"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::Medium, "CORS bypass attempt detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &CorsDetector,
            input,
            AttackCategory::Protocol,
            Severity::Medium,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&CorsDetector, input);
    }

    #[test]
    fn name_is_cors() {
        assert_eq!(CorsDetector.name(), "cors");
    }

    #[test]
    fn detects_null_origin() {
        assert_detected("Origin: null");
        assert_detected("Origin:null");
    }

    #[test]
    fn detects_wildcard_allow_origin() {
        assert_detected("Access-Control-Allow-Origin: *");
        assert_detected("Access-Control-Allow-Origin:*");
    }

    #[test]
    fn detects_allow_credentials() {
        assert_detected("Access-Control-Allow-Credentials: true");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("origin: NULL");
        assert_detected("access-control-allow-origin: *");
    }

    #[test]
    fn rejects_benign_headers() {
        assert_clean("Origin: http://example.com");
        assert_clean("Access-Control-Allow-Origin: https://example.com");
        assert_clean("Access-Control-Allow-Credentials: false");
        assert_clean("Origin: *");
    }

    #[test]
    fn rejects_space_before_colon() {
        assert_clean("Access-Control-Allow-Origin : *");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("跨域配置说明，无攻击");
    }
}
