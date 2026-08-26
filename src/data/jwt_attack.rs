// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"(?i)"alg"\s*:\s*"none""#).unwrap(),
        Regex::new(r#"(?i)"alg"\s*:\s*"None""#).unwrap(),
        Regex::new(r#"(?i)"alg"\s*:\s*"NONE""#).unwrap(),
        Regex::new(r#"(?i)"kid"\s*:.*\.\.\/"#).unwrap(),
        Regex::new(r#"(?i)"kid"\s*:.*\.\.\\"#).unwrap(),
        Regex::new(r#"(?i)"kid"\s*:.*/dev/null"#).unwrap(),
        Regex::new(r"ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[\s]*").unwrap(),
        Regex::new(r"ey[A-Za-z0-9_-]+\.[\s]*\.[A-Za-z0-9_-]+").unwrap(),
    ]
});

pub struct JwtAttackDetector;

impl Detector for JwtAttackDetector {
    fn name(&self) -> &'static str {
        "jwt_attack"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "jwt_attack".into(),
                    category: AttackCategory::Data,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "JWT attack detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackCategory, Detector, Severity};

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(JwtAttackDetector.name(), "jwt_attack");
    }

    #[test]
    fn detects_none_algorithm() {
        for payload in [
            r#"{"alg": "none", "typ": "JWT"}"#,
            r#"{"alg":"None"}"#,
            r#"{"alg": "NONE"}"#,
            r#"{"alg": "noNe"}"#,
        ] {
            let r = JwtAttackDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "jwt_attack");
            assert_eq!(r.category, AttackCategory::Data);
            assert_eq!(r.severity, Severity::High);
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_kid_traversal() {
        for payload in [
            r#"{"kid": "../../etc/passwd"}"#,
            r#"{"kid": "/dev/null"}"#,
            r#"{"kid": "..\\..\\key"}"#,
        ] {
            let r = JwtAttackDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_token_shape() {
        for payload in [
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.",
            "eyJhbGciOiJIUzI1NiJ9. .abc123",
        ] {
            let r = JwtAttackDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            r#"{"alg": "HS256"}"#,
            r"{'alg': 'none'}",
            r#"{"kid": "key-1"}"#,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ",
            "The eye color is blue",
        ] {
            assert!(
                JwtAttackDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(JwtAttackDetector.detect("").is_none());
        assert!(JwtAttackDetector.detect("   ").is_none());
        assert!(JwtAttackDetector.detect("алгоритм: none").is_none());
    }
}
