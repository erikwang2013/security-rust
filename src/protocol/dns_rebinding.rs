// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

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
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "dns_rebinding".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "DNS rebinding attack detected".into(),
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
        let r = DnsRebindingDetector
            .detect(input)
            .expect("expected dns_rebinding detection");
        assert_eq!(r.attack_type, "dns_rebinding");
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
            DnsRebindingDetector.detect(input).is_none(),
            "not detected: {input:?}"
        );
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
