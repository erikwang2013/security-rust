// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"\{\{.*?\}\}").unwrap(),
        Regex::new(r"\$\{.*?\}").unwrap(),
        Regex::new(r"\{%\s*.*?\s*%\}").unwrap(),
        Regex::new(r"<%=").unwrap(),
        Regex::new(r"<%@").unwrap(),
        Regex::new(r"#set\s*\(").unwrap(),
        Regex::new(r"__mro__").unwrap(),
        Regex::new(r"__subclasses__").unwrap(),
        Regex::new(r"__globals__").unwrap(),
        Regex::new(r"__builtins__").unwrap(),
        Regex::new(r"__class__").unwrap(),
    ]
});

pub struct SstiDetector;

impl Detector for SstiDetector {
    fn name(&self) -> &'static str {
        "ssti"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Injection, Severity::Critical, "Server-Side Template Injection detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SstiDetector {
        SstiDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::Critical,
        );
    }

    #[test]
    fn name_is_ssti() {
        assert_eq!(det().name(), "ssti");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "{{7*7}}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "${7*7}",
            "{% include '/etc/passwd' %}",
            "<%= params[:x] %>",
            r#"<%@ page import="java.util.*" %>"#,
            "#set($x = 5)",
            "{{config.__init__.__globals__}}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The total is $5.00 plus tax",
            "Please enter your name below",
            "The class of 2026 graduates in May",
            "100% of users agree with this",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: delimiters incomplete, or magic names uppercase (case-sensitive)
        assert!(det().detect("{7*7}").is_none());
        assert!(det().detect("{{7*7").is_none());
        assert!(det().detect("__CLASS__").is_none());
        assert!(det().detect("{$x=7}").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "{{ ''.__class__.__MRO__[1] }}",
            "{{ self.__dict__ }}",
            "{{request.application.__globals__}}",
        ] {
            assert_hit(input);
        }
    }
}
