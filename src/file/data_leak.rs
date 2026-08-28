// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

static CC_PAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap()
});

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        Regex::new(r"-----BEGIN\s*(?:RSA\s*)?PRIVATE\s*KEY").unwrap(),
        Regex::new(r"-----BEGIN\s*CERTIFICATE").unwrap(),
        Regex::new(r"-----BEGIN\s*DSA\s*PRIVATE").unwrap(),
        Regex::new(r"-----BEGIN\s*EC\s*PRIVATE").unwrap(),
        Regex::new(r"-----BEGIN\s*PGP\s*PRIVATE").unwrap(),
        Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
        Regex::new(r"(?i)mongodb(?:\+srv)?://[^/\s]+").unwrap(),
        Regex::new(r"(?i)mysql://[^/\s]+").unwrap(),
        Regex::new(r"(?i)postgres(?:ql)?://[^/\s]+").unwrap(),
        Regex::new(r"(?i)redis://[^/\s]+").unwrap(),
        Regex::new(r"(?i)jdbc:[a-z]+://").unwrap(),
    ]
});

fn luhn_valid(pan: &str) -> bool {
    let mut len = 0;
    let mut sum = 0u32;
    for (i, b) in pan.bytes().rev().filter(|b| b.is_ascii_digit()).enumerate() {
        len += 1;
        let d = (b - b'0') as u32;
        if i % 2 == 1 {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
    }
    len >= 13 && sum.is_multiple_of(10)
}

pub struct DataLeakDetector;

impl Detector for DataLeakDetector {
    fn name(&self) -> &'static str {
        "data_leak"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        if let Some(m) = CC_PAN.find(input)
            && luhn_valid(m.as_str())
        {
            return Some(DetectionResult {
                attack_type: self.name().into(),
                category: AttackCategory::File,
                severity: Severity::Critical,
                matched_pattern: m.as_str().to_string(),
                offset: m.start(),
                message: "Sensitive data leak detected (credit card)".into(),
            });
        }
        regex_detect(&PATTERNS, self.name(), AttackCategory::File, Severity::Critical, "Sensitive data leak detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(DataLeakDetector.name(), "data_leak");
    }

    #[test]
    fn detects_valid_credit_cards() {
        for payload in ["4111111111111111", "4242424242424242", "5555555555554444"] {
            let r = DataLeakDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "data_leak");
            assert_eq!(r.category, AttackCategory::File);
            assert_eq!(r.severity, Severity::Critical);
            assert_eq!(r.matched_pattern, payload);
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_cloud_and_api_keys() {
        for payload in [
            "AKIAIOSFODNN7EXAMPLE",
            "AWS_ACCESS_KEY=AKIA1234567890ABCDEF",
            "sk-abcdefghijklmnopqrstuvwxyz123456",
            "key=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
        ] {
            let r = DataLeakDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_private_keys_and_certificates() {
        for payload in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN CERTIFICATE-----",
        ] {
            let r = DataLeakDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_database_connection_strings() {
        for payload in [
            "mongodb://admin:password@localhost:27017/db",
            "mongodb+srv://admin@cluster.example.com/db",
            "mysql://root:secret@db:3306/app",
            "postgresql://user:pass@pg:5432/db",
            "postgres://user:pass@pg:5432/db",
            "redis://:secret@cache:6379/0",
            "jdbc:mysql://localhost:3306/app",
        ] {
            let r = DataLeakDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "4111111111111112",
            "AKIA",
            "AKIAIOSFODNN7EXAMPL",
            "sk-ab",
            "-----BEGIN PUBLIC KEY-----",
            "mongodb",
            "mysql://",
            "redis://",
            "https://example.com/db",
            "jdbc:mysql:thin@localhost",
        ] {
            assert!(
                DataLeakDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(DataLeakDetector.detect("").is_none());
        assert!(DataLeakDetector.detect("   ").is_none());
        assert!(DataLeakDetector.detect("カード番号は秘密です").is_none());
        assert!(
            DataLeakDetector
                .detect("card 4111 1111 1111 1111")
                .is_none()
        ); // spaced digits
    }
}
