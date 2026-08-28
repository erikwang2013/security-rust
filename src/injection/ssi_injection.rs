// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
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
        regex_detect(&PATTERNS, self.name(), AttackCategory::Injection, Severity::High, "SSI Server-Side Include injection detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SsiInjectionDetector {
        SsiInjectionDetector
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
    fn name_is_ssi_injection() {
        assert_eq!(det().name(), "ssi_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            r#"<!--#exec cmd="cat /etc/passwd"-->"#,
            r#"<!--#include file="/etc/passwd"-->"#,
            r#"<!--#echo var="DATE_LOCAL"-->"#,
            r#"<!--#fsize file="index.html"-->"#,
            r#"<!--#flastmod file="index.html"-->"#,
            r#"<!--#config timefmt="%B"-->"#,
            r#"<!--#printenv-->"#,
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "<!-- this is a plain comment -->",
            "The page was generated at 3:00 PM",
            "Include the file below the table",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: directive incomplete, or uppercase (patterns are case-sensitive)
        assert!(det().detect("<!--#exec").is_none());
        assert!(det().detect(r#"<!--#EXEC cmd="ls"-->"#).is_none());
        assert!(det().detect("<!-- #exec cmd=\"ls\" -->").is_none());
    }
}
