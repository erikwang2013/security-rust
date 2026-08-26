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

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> GraphQlInjectionDetector {
        GraphQlInjectionDetector
    }

    fn assert_hit(input: &str) {
        let r = det()
            .detect(input)
            .expect("expected GraphQL injection detection");
        assert_eq!(r.attack_type, "graphql_injection");
        assert_eq!(r.category, AttackCategory::Injection);
        assert_eq!(r.severity, Severity::Medium);
        assert!(!r.matched_pattern.is_empty(), "matched_pattern empty");
        assert!(
            r.offset <= input.len(),
            "offset {} > len {}",
            r.offset,
            input.len()
        );
    }

    #[test]
    fn name_is_graphql_injection() {
        assert_eq!(det().name(), "graphql_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "{ __schema { types { name } } }",
            "query { __type { name } }",
            "query { __typename }",
            "{a{b{c{d{e{f}}}}}}",
            "fragment F on __Type { name }",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "query { user(id: 1) { name } }",
            r#"{"a": {"b": {"c": {"d": 1}}}}"#,
            "The schema was updated today",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: not quite the introspection keyword, or not deep enough
        assert!(det().detect("{__schem}").is_none());
        assert!(det().detect("schema").is_none());
        assert!(det().detect("{{{{").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in ["{ __SCHEMA { types } }", "__TYPENAME", "__Type { name }"] {
            assert_hit(input);
        }
    }
}
