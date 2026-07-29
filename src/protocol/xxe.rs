// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)<!ENTITY\s+").unwrap(),
        Regex::new(r#"(?i)SYSTEM\s+["']"#).unwrap(),
        Regex::new(r#"(?i)PUBLIC\s+["']"#).unwrap(),
        Regex::new(r"(?i)<!ENTITY\s+%").unwrap(),
        Regex::new(r"(?i)<!DOCTYPE\s+").unwrap(),
    ]
});

pub struct XxeDetector;

impl Detector for XxeDetector {
    fn name(&self) -> &'static str {
        "xxe"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "xxe".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "XXE XML External Entity attack detected".into(),
                });
            }
        }
        None
    }
}
