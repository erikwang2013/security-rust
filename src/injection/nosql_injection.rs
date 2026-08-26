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

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> NoSqlInjectionDetector {
        NoSqlInjectionDetector
    }

    fn assert_hit(input: &str) {
        let r = det()
            .detect(input)
            .expect("expected NoSQL injection detection");
        assert_eq!(r.attack_type, "nosql_injection");
        assert_eq!(r.category, AttackCategory::Injection);
        assert_eq!(r.severity, Severity::Critical);
        assert!(!r.matched_pattern.is_empty(), "matched_pattern empty");
        assert!(
            r.offset <= input.len(),
            "offset {} > len {}",
            r.offset,
            input.len()
        );
    }

    #[test]
    fn name_is_nosql_injection() {
        assert_eq!(det().name(), "nosql_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            r#"{"username": {"$ne": ""}}"#,
            r#"{"$gt": ""}"#,
            r#"{"user": {"$regex": "^admin"}}"#,
            r#"{"$or": [{"role": "admin"}]}"#,
            r#"{'$ne': ''}"#,
            r#"{"pass": {"$nin": ["a"]}}"#,
            r#"db.users.find({"$where": "sleep(5000)"})"#,
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            r#"{"name": "John", "age": 30, "city": "New York"}"#,
            r#"{"price": "$5.99"}"#,
            "The total cost is $100 and the discount is 10%",
            "The equation is simple to solve",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect("  \t ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: operator without colon or without dollar sign
        assert!(det().detect(r#"{"$ne"}"#).is_none());
        assert!(det().detect(r#"{"ne": ""}"#).is_none());
        assert!(det().detect("age > 18").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [r#"{"$NE": ""}"#, r#"{"$GTE": 5}"#, r#"{"$REGEX": "^a"}"#] {
            assert_hit(input);
        }
    }
}
