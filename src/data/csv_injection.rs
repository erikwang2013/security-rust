use regex::Regex;
use std::sync::LazyLock;
use crate::{AttackCategory, DetectionResult, Detector, Severity};

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
