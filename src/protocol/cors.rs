// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Origin:\s*null").unwrap(),
        Regex::new(r"(?i)Access-Control-Allow-Origin:\s*\*").unwrap(),
        Regex::new(r"(?i)Access-Control-Allow-Credentials:\s*true").unwrap(),
    ]
});

pub struct CorsDetector;

impl Detector for CorsDetector {
    fn name(&self) -> &'static str {
        "cors"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "cors".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "CORS bypass attempt detected".into(),
                });
            }
        }
        None
    }
}
