// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\r\n.*Host:").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Forwarded").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Forwarded-Host").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Original-URL").unwrap(),
        Regex::new(r"(?i)\r\n.*X-Rewrite-URL").unwrap(),
    ]
});

pub struct HostHeaderDetector;

impl Detector for HostHeaderDetector {
    fn name(&self) -> &'static str {
        "host_header"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "host_header".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Host header attack detected".into(),
                });
            }
        }
        None
    }
}
