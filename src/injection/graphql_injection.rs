// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)__schema").unwrap(),
        Regex::new(r"(?i)__type\s*\{").unwrap(),
        Regex::new(r"(?i)__typename").unwrap(),
        Regex::new(r"\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{").unwrap(),
    ]
});

pub struct GraphQlInjectionDetector;

impl Detector for GraphQlInjectionDetector {
    fn name(&self) -> &'static str {
        "graphql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "graphql_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "GraphQL injection/introspection detected".into(),
                });
            }
        }
        None
    }
}
