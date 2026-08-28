// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)//[^/\s]+\.[a-z]{2,}").unwrap(),
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
        Regex::new(r"(?i)data\s*:\s*text/plain").unwrap(),
    ]
});

pub struct OpenRedirectDetector;

impl Detector for OpenRedirectDetector {
    fn name(&self) -> &'static str {
        "open_redirect"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            for m in re.find_iter(input) {
                let start = m.start();
                // Skip // matches that are part of a URL scheme (e.g. https://)
                if start > 0 && input.as_bytes()[start - 1] == b':' {
                    continue;
                }
                return Some(DetectionResult {
                    attack_type: "open_redirect".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: start,
                    message: "Open redirect detected".into(),
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
        crate::test_helpers::assert_detected(
            &OpenRedirectDetector,
            input,
            AttackCategory::Protocol,
            Severity::Medium,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&OpenRedirectDetector, input);
    }

    #[test]
    fn name_is_open_redirect() {
        assert_eq!(OpenRedirectDetector.name(), "open_redirect");
    }

    #[test]
    fn detects_double_slash_url() {
        assert_detected("//evil.com/phishing");
        assert_detected("//attacker.org/steal?u=1");
        assert_detected("https://ok.com//evil.com"); // scheme match skipped, later redirect still caught
    }

    #[test]
    fn detects_javascript_uri() {
        assert_detected("javascript:alert(document.cookie)");
    }

    #[test]
    fn detects_data_html_uri() {
        assert_detected("data:text/html,<script>alert(1)</script>");
    }

    #[test]
    fn detects_data_plain_uri() {
        assert_detected("data: text/plain;base64,SGVsbG8=");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("JAVASCRIPT:alert(1)");
        assert_detected("//Evil.Com/");
    }

    #[test]
    fn rejects_scheme_urls() {
        assert_clean("https://evil.com/phishing");
        assert_clean("http://example.com/");
        assert_clean("file:///etc/passwd");
    }

    #[test]
    fn rejects_benign_paths() {
        assert_clean("example.com/redirect");
        assert_clean("java script: alert(1)");
        assert_clean("data:image/png;base64,AA==");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("//evil/com");
        assert_clean("//evil.c");
        assert_clean("// evil.com");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("重定向到登录页");
    }
}
