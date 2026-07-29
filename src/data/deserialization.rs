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
