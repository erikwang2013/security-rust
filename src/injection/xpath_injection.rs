use crate::{AttackCategory, DetectionResult, Detector, Severity};
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
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "xpath_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "XPATH injection detected".into(),
                });
            }
        }
        None
    }
}
