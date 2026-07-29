// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"<!--#exec cmd=").unwrap(),
        Regex::new(r"<!--#include file=").unwrap(),
        Regex::new(r"<!--#echo var=").unwrap(),
        Regex::new(r"<!--#fsize").unwrap(),
        Regex::new(r"<!--#flastmod").unwrap(),
        Regex::new(r"<!--#config").unwrap(),
        Regex::new(r"<!--#printenv").unwrap(),
    ]
});

pub struct SsiInjectionDetector;

impl Detector for SsiInjectionDetector {
    fn name(&self) -> &'static str {
        "ssi_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "ssi_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "SSI Server-Side Include injection detected".into(),
                });
            }
        }
        None
    }
}
