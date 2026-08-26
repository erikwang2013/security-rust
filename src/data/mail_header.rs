// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Bcc\s*:").unwrap(),
        Regex::new(r"(?i)Cc\s*:").unwrap(),
        Regex::new(r"(?i)From\s*:.*\r?\n.*From\s*:").unwrap(),
        Regex::new(r"(?i)MIME-Version\s*:").unwrap(),
        Regex::new(r"(?i)Content-Type\s*:.*multipart").unwrap(),
        Regex::new(r"(?i)boundary\s*=").unwrap(),
    ]
});

pub struct MailHeaderDetector;

impl Detector for MailHeaderDetector {
    fn name(&self) -> &'static str {
        "mail_header"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "mail_header".into(),
                    category: AttackCategory::Data,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Mail header injection detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackCategory, Detector, Severity};

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(MailHeaderDetector.name(), "mail_header");
    }

    #[test]
    fn detects_injected_recipient_headers() {
        for payload in [
            "Bcc: victim@evil.com",
            "Cc: victim@evil.com",
            "bcc: lower@case.com",
        ] {
            let r = MailHeaderDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "mail_header");
            assert_eq!(r.category, AttackCategory::Data);
            assert_eq!(r.severity, Severity::Medium);
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
    fn detects_double_from_and_mime_headers() {
        for payload in [
            "From: a@b.c\nFrom: c@d.e",
            "From: a@b.c\r\nFrom: c@d.e",
            "MIME-Version: 1.0",
            "Content-Type: multipart/mixed; boundary=abc123",
            "boundary=abc123",
        ] {
            let r = MailHeaderDetector
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
            "Bcc victim@evil.com",
            "From: a@b.c",
            "Content-Type: text/plain",
            "boundary abc",
            "MIME-Version",
            "multipart/form-data",
        ] {
            assert!(
                MailHeaderDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(MailHeaderDetector.detect("").is_none());
        assert!(MailHeaderDetector.detect("   ").is_none());
        assert!(
            MailHeaderDetector
                .detect("ＢＣＣ: evil@example.com")
                .is_none()
        ); // fullwidth letters
    }
}
