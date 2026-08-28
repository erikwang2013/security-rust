// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Host:\s*127\.").unwrap(),
        Regex::new(r"(?i)Host:\s*10\.").unwrap(),
        Regex::new(r"(?i)Host:\s*192\.168\.").unwrap(),
        Regex::new(r"(?i)Host:\s*172\.(1[6-9]|2\d|3[01])").unwrap(),
        Regex::new(r"(?i)Host:\s*localhost").unwrap(),
        Regex::new(r"(?i)Host:\s*\[::1\]").unwrap(),
        Regex::new(r"(?i)Host:\s*0\.0\.0\.0").unwrap(),
    ]
});

pub struct DnsRebindingDetector;

impl Detector for DnsRebindingDetector {
    fn name(&self) -> &'static str {
        "dns_rebinding"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::High, "DNS rebinding attack detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &DnsRebindingDetector,
            input,
            AttackCategory::Protocol,
            Severity::High,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&DnsRebindingDetector, input);
    }

    #[test]
    fn name_is_dns_rebinding() {
        assert_eq!(DnsRebindingDetector.name(), "dns_rebinding");
    }

    #[test]
    fn detects_loopback_host() {
        assert_detected("Host: 127.0.0.1");
    }

    #[test]
    fn detects_private_hosts() {
        assert_detected("Host: 10.0.0.2");
        assert_detected("Host: 192.168.1.1");
        assert_detected("Host: 172.16.0.1");
        assert_detected("Host: 172.31.255.255");
    }

    #[test]
    fn detects_local_names() {
        assert_detected("Host: localhost");
        assert_detected("Host: [::1]");
        assert_detected("Host: 0.0.0.0");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("host: 127.0.0.1");
    }

    #[test]
    fn rejects_public_hosts() {
        assert_clean("Host: example.com");
        assert_clean("Host: 8.8.8.8");
        assert_clean("Host: 172.32.0.1");
    }

    #[test]
    fn rejects_hostname_variants() {
        assert_clean("Hostname: 127.0.0.1");
        assert_clean("Hostname: localhost");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("Host: 12.7.0.1");
        assert_clean("Host: 172.15.0.1");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("主机名解析测试，无攻击");
    }
}
