// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)169\.254\.169\.254").unwrap(),
        Regex::new(r"(?i)10\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
        Regex::new(r"(?i)172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}").unwrap(),
        Regex::new(r"(?i)192\.168\.\d{1,3}\.\d{1,3}").unwrap(),
        Regex::new(r"(?i)127\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
        Regex::new(r"(?i)\[::1\]").unwrap(),
        Regex::new(r"(?i)0\.0\.0\.0").unwrap(),
        Regex::new(r"(?i)gopher://").unwrap(),
        Regex::new(r"(?i)dict://").unwrap(),
        Regex::new(r"(?i)ftp://[^/]*@").unwrap(),
        Regex::new(r"(?i)file:///").unwrap(),
    ]
});

pub struct SsrfDetector;

impl Detector for SsrfDetector {
    fn name(&self) -> &'static str {
        "ssrf"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::Critical, "SSRF server-side request forgery detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &SsrfDetector,
            input,
            AttackCategory::Protocol,
            Severity::Critical,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&SsrfDetector, input);
    }

    #[test]
    fn name_is_ssrf() {
        assert_eq!(SsrfDetector.name(), "ssrf");
    }

    #[test]
    fn detects_cloud_metadata_ip() {
        assert_detected("http://169.254.169.254/latest/meta-data/");
    }

    #[test]
    fn detects_internal_ipv4() {
        assert_detected("http://10.0.0.1/admin");
    }

    #[test]
    fn detects_private_ranges() {
        assert_detected("http://192.168.1.1/");
        assert_detected("http://172.16.0.1/");
        assert_detected("http://172.31.255.255/");
        assert_detected("http://127.0.0.1:8080/");
        assert_detected("http://0.0.0.0/");
        assert_detected("http://[::1]/");
    }

    #[test]
    fn detects_ssrf_uri_schemes() {
        assert_detected("gopher://evil.com/_GET / HTTP/1.1");
        assert_detected("dict://evil.com:11211/");
        assert_detected("ftp://user@evil.com/file");
        assert_detected("file:///etc/passwd");
    }

    #[test]
    fn detects_mixed_case_schemes() {
        assert_detected("GOPHER://evil.com/");
        assert_detected("FILE:///etc/shadow");
    }

    #[test]
    fn rejects_public_hosts() {
        assert_clean("http://example.com/index.html");
        assert_clean("https://github.com/security-rust");
        assert_clean("http://172.32.0.1/");
        assert_clean("http://8.8.8.8/dns");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("http://10.0.0/admin");
        assert_clean("http://169.254.169/admin");
        assert_clean("ftp://evil.com/pub");
        assert_clean("http://192.168/admin");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
        assert_clean("\t\n");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("你好，世界！这是一个正常的中文文本。");
    }
}
