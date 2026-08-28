// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)__proto__").unwrap(),
        Regex::new(r"(?i)constructor\[").unwrap(),
        Regex::new(r"(?i)constructor\.prototype").unwrap(),
        Regex::new(r"(?i)__defineGetter__").unwrap(),
        Regex::new(r"(?i)__defineSetter__").unwrap(),
        Regex::new(r"(?i)__lookupGetter__").unwrap(),
        Regex::new(r"(?i)__lookupSetter__").unwrap(),
        Regex::new(r"(?i)hasOwnProperty\[").unwrap(),
    ]
});

pub struct PrototypePollutionDetector;

impl Detector for PrototypePollutionDetector {
    fn name(&self) -> &'static str {
        "prototype_pollution"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Data, Severity::High, "JavaScript prototype pollution detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(PrototypePollutionDetector.name(), "prototype_pollution");
    }

    #[test]
    fn detects_proto_and_constructor_payloads() {
        for payload in [
            r#"{"__proto__": {"isAdmin": true}}"#,
            r#"{"__proto__": {"polluted": true}}"#,
            "obj.constructor.prototype.isAdmin = true",
            "a[constructor[0]]",
            "o[__proto__][isAdmin]",
        ] {
            let r = PrototypePollutionDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "prototype_pollution");
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
    fn detects_legacy_getter_setter_apis() {
        for payload in [
            "__defineGetter__('x', fn)",
            "__defineSetter__('x', fn)",
            "__lookupGetter__('x')",
            "__lookupSetter__('x')",
            "hasOwnProperty['isAdmin']",
        ] {
            let r = PrototypePollutionDetector
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
            "constructor",
            "hasOwnProperty",
            "proto",
            "the prototype chain is a concept",
        ] {
            assert!(
                PrototypePollutionDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(PrototypePollutionDetector.detect("").is_none());
        assert!(PrototypePollutionDetector.detect("   ").is_none());
        assert!(PrototypePollutionDetector.detect("＿＿proto＿＿").is_none()); // fullwidth underscores
        assert!(PrototypePollutionDetector.detect("Прототип").is_none());
    }
}
