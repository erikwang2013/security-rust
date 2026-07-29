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
