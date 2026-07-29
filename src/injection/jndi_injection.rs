// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\$\{jndi:").unwrap(),
        Regex::new(r"(?i)\$\{lower:j\}").unwrap(),
        Regex::new(r"(?i)\$\{upper:j\}").unwrap(),
        Regex::new(r"(?i)\$\{::-j\}").unwrap(),
        Regex::new(r"(?i)\$\{env:").unwrap(),
        Regex::new(r"(?i)\$\{sys:").unwrap(),
        Regex::new(r"(?i)\$\{java:").unwrap(),
    ]
});

pub struct JndiInjectionDetector;

impl Detector for JndiInjectionDetector {
    fn name(&self) -> &'static str {
        "jndi_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "jndi_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "JNDI/Log4Shell injection detected".into(),
                });
            }
        }
        None
    }
}
