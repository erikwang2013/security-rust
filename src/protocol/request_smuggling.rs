// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Transfer-Encoding:.*\r\n.*Transfer-Encoding:").unwrap(),
        Regex::new(r"(?i)Transfer-Encoding:[\s]*chunked").unwrap(),
    ]
});

pub struct RequestSmugglingDetector;

impl Detector for RequestSmugglingDetector {
    fn name(&self) -> &'static str {
        "request_smuggling"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "request_smuggling".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "HTTP request smuggling detected".into(),
                });
            }
        }
        None
    }
}
