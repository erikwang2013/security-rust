// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

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
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "ssrf".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "SSRF server-side request forgery detected".into(),
                });
            }
        }
        None
    }
}
