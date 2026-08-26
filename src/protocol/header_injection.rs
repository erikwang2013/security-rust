// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)%0[dD]%0[aA]").unwrap(),
        Regex::new(
            r"(?i)\r\n\s*(?:Set-Cookie|Location|Content-Length|Content-Type|Transfer-Encoding):",
        )
        .unwrap(),
        Regex::new(r"(?i)%0[dD].*%0[aA]").unwrap(),
    ]
});

pub struct HeaderInjectionDetector;

impl Detector for HeaderInjectionDetector {
    fn name(&self) -> &'static str {
        "header_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "header_injection".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "HTTP header injection (CRLF) detected".into(),
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
        let r = HeaderInjectionDetector
            .detect(input)
            .expect("expected header_injection detection");
        assert_eq!(r.attack_type, "header_injection");
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
            HeaderInjectionDetector.detect(input).is_none(),
            "not detected: {input:?}"
        );
    }

    #[test]
    fn name_is_header_injection() {
        assert_eq!(HeaderInjectionDetector.name(), "header_injection");
    }

    #[test]
    fn detects_encoded_crlf_set_cookie() {
        assert_detected("test%0d%0aSet-Cookie: evil=true");
    }

    #[test]
    fn detects_encoded_crlf_location() {
        assert_detected("redirect?url=%0D%0ALocation: /admin");
    }

    #[test]
    fn detects_encoded_crlf_content_length() {
        assert_detected("body%0d%0aContent-Length: 0");
    }

    #[test]
    fn detects_raw_crlf_headers() {
        assert_detected("foo\r\nContent-Type: text/html");
        assert_detected("bar\r\nTransfer-Encoding: chunked");
    }

    #[test]
    fn detects_scattered_encoded_crlf() {
        assert_detected("a%0dcontent%0a");
    }

    #[test]
    fn rejects_clean_headers() {
        assert_clean("Set-Cookie: evil=true");
        assert_clean("Location: /index.php");
        assert_clean("Content-Type: text/html");
    }

    #[test]
    fn rejects_lone_encoded_chars() {
        assert_clean("%0d");
        assert_clean("%0a");
        assert_clean("test%0dend");
        assert_clean("%0d%0d");
    }

    #[test]
    fn rejects_lf_only_newlines() {
        assert_clean("foo\nContent-Type: text/html");
        assert_clean("foo\nLocation: /x");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("foo\r\nContent-Type text/html");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
        assert_clean("\r\n");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("这是一段正常文本，无注入");
    }
}
