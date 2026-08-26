// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"O:\d+:"#).unwrap(),
        Regex::new(r#"C:\d+:"#).unwrap(),
        Regex::new(r"(?i)unserialize\s*\(").unwrap(),
        Regex::new(r"(?i)__wakeup").unwrap(),
        Regex::new(r"(?i)__destruct").unwrap(),
        Regex::new(r"(?i)__construct").unwrap(),
        Regex::new(r"(?i)__toString").unwrap(),
        Regex::new(r"(?i)__call").unwrap(),
        Regex::new(r"(?i)__get").unwrap(),
        Regex::new(r"(?i)__set").unwrap(),
        Regex::new(r"a:\d+:\{").unwrap(),
    ]
});

pub struct DeserializationDetector;

impl Detector for DeserializationDetector {
    fn name(&self) -> &'static str {
        "deserialization"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "deserialization".into(),
                    category: AttackCategory::Data,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "PHP deserialization attack detected".into(),
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
        assert_eq!(DeserializationDetector.name(), "deserialization");
    }

    #[test]
    fn detects_serialized_php_object() {
        let input = r#"O:8:"stdClass":1:{s:4:"test";s:5:"value";}"#;
        let r = DeserializationDetector
            .detect(input)
            .expect("serialized PHP object should be detected");
        assert_eq!(r.attack_type, "deserialization");
        assert_eq!(r.category, AttackCategory::Data);
        assert_eq!(r.severity, Severity::Critical);
        assert_eq!(r.offset, 0);
    }

    #[test]
    fn detects_serialized_arrays_and_magic_methods() {
        for payload in [
            r#"a:1:{s:4:"key";s:5:"value";}"#,
            r#"C:5:"Foo":0:{}"#,
            "unserialize($_POST['data'])",
            "trigger __wakeup magic method",
            "call __destruct on shutdown",
            "override __toString()",
        ] {
            let r = DeserializationDetector
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
            "Order: 8 items please",
            "O:8",
            "unserialize_data is not a call",
            "constructor and destructor in C++",
            "a:b:{not a serialized array}",
        ] {
            assert!(
                DeserializationDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(DeserializationDetector.detect("").is_none());
        assert!(DeserializationDetector.detect("   ").is_none());
        assert!(
            DeserializationDetector
                .detect("日本語のテキストです")
                .is_none()
        );
    }
}
