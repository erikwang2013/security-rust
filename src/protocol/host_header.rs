// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\r\n.*Host:").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Forwarded").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Forwarded-Host").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Original-URL").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Rewrite-URL").unwrap(),
    ]
});

pub struct HostHeaderDetector;

impl Detector for HostHeaderDetector {
    fn name(&self) -> &'static str {
        "host_header"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "host_header".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Host header attack detected".into(),
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
        let r = HostHeaderDetector
            .detect(input)
            .expect("expected host_header detection");
        assert_eq!(r.attack_type, "host_header");
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
            HostHeaderDetector.detect(input).is_none(),
            "not detected: {input:?}"
        );
    }

    #[test]
    fn name_is_host_header() {
        assert_eq!(HostHeaderDetector.name(), "host_header");
    }

    #[test]
    fn detects_x_forwarded_host() {
        assert_detected("Host: example.com\r\nX-Forwarded-Host: evil.com");
    }

    #[test]
    fn detects_injected_host_line() {
        assert_detected("GET / HTTP/1.1\r\nHost: evil.com");
    }

    #[test]
    fn detects_x_original_url() {
        assert_detected("Host: a.com\r\nX-Original-URL: /admin");
    }

    #[test]
    fn detects_x_rewrite_url() {
        assert_detected("Host: a.com\r\nX-Rewrite-URL: /admin");
    }

    #[test]
    fn detects_x_forwarded_for() {
        assert_detected("Host: a.com\r\nX-Forwarded-For: 1.2.3.4");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("host: example.com\r\nx-forwarded-host: evil.com");
    }

    #[test]
    fn rejects_single_header_lines() {
        assert_clean("Host: example.com");
        assert_clean("X-Forwarded-Host: evil.com");
        assert_clean("Host: example.com\r\nAccept: */*");
    }

    #[test]
    fn rejects_lf_only_newlines() {
        assert_clean("Host: example.com\nX-Forwarded-Host: evil.com");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("主机头示例，无攻击");
    }
}
