// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#""(?i)\$ne"\s*:"#).unwrap(),
        Regex::new(r#"'(?i)\$ne'\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$gt"\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$gte"\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$lt"\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$lte"\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$regex"\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$where"\s*:"#).unwrap(),
        Regex::new(r#""(?i)\$or"\s*:"#).unwrap(),
        Regex::new(r"(?i)\$eq").unwrap(),
        Regex::new(r"(?i)\$nin").unwrap(),
        Regex::new(r#"\{\s*"\$gt"\s*:\s*""\s*\}"#).unwrap(),
    ]
});

pub struct NoSqlInjectionDetector;

impl Detector for NoSqlInjectionDetector {
    fn name(&self) -> &'static str {
        "nosql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "nosql_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "NoSQL injection detected".into(),
                });
            }
        }
        None
    }
}
