// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"^[=+\-@\t\r]").unwrap(),
        Regex::new(r"(?i)^\s*DDE").unwrap(),
        Regex::new(r"(?i)^\s*cmd\s*\|").unwrap(),
        Regex::new(r"(?i)^\s*@SUM\s*\(").unwrap(),
    ]
});

pub struct CsvInjectionDetector;

impl Detector for CsvInjectionDetector {
    fn name(&self) -> &'static str {
        "csv_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "csv_injection".into(),
                    category: AttackCategory::Data,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "CSV formula injection detected".into(),
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
        assert_eq!(CsvInjectionDetector.name(), "csv_injection");
    }

    #[test]
    fn detects_formula_prefixes() {
        for payload in [
            "=cmd|' /C calc'!A0",
            "+1+1",
            "-2+3",
            "@SUM(1+1)*cmd",
            "\t=1",
            "DDE;cmd",
            "cmd|' /C calc'!A0",
        ] {
            let r = CsvInjectionDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "csv_injection");
            assert_eq!(r.category, AttackCategory::Data);
            assert_eq!(r.severity, Severity::Medium);
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
            "a=1+1",
            "SUM(1+1)",
            "cmd /C calc",
            "not a formula",
        ] {
            assert!(
                CsvInjectionDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(CsvInjectionDetector.detect("").is_none());
        assert!(CsvInjectionDetector.detect("   ").is_none());
        assert!(CsvInjectionDetector.detect("＝cmd|' /C calc'!A0").is_none()); // fullwidth equals
    }
}
