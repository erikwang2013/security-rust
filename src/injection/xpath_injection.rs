// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"'(?i)\s*or\s*'1'\s*=\s*'1").unwrap(),
        Regex::new(r"'(?i)\s*and\s*'1'\s*=\s*'2").unwrap(),
        Regex::new(r"'(?i)\s*or\s*1\s*=\s*1").unwrap(),
        Regex::new(r#""(?i)\s*or\s*"1"\s*=\s*"1"#).unwrap(),
        Regex::new(r"'\s*\]\s*\|\s*").unwrap(),
        Regex::new(r"'(?i)\s*or\s*''='").unwrap(),
        Regex::new(r"'(?i)\s*or\s*true\s*\(").unwrap(),
    ]
});

pub struct XPathInjectionDetector;

impl Detector for XPathInjectionDetector {
    fn name(&self) -> &'static str {
        "xpath_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Injection, Severity::High, "XPATH injection detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> XPathInjectionDetector {
        XPathInjectionDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::High,
        );
    }

    #[test]
    fn name_is_xpath_injection() {
        assert_eq!(det().name(), "xpath_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "' or '1'='1",
            "' or 1=1",
            "' and '1'='2",
            r#"" or "1"="1"#,
            "' or ''='",
            "' or true()",
            "']|//admin",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The first quarter results are in",
            "or is a conjunction in English",
            "I want 1 pizza and 1 drink",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: quote missing or condition not satisfied
        assert!(det().detect("or 1=1").is_none());
        assert!(det().detect("' or '2'='1").is_none());
        assert!(det().detect("' or 2=2").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in ["' OR '1'='1", "' And '1'='2", r#"" Or "1"="1"#] {
            assert_hit(input);
        }
    }
}
