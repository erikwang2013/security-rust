use regex::Regex;
use std::sync::LazyLock;
use crate::{AttackCategory, DetectionResult, Detector, Severity};

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
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "prototype_pollution".into(),
                    category: AttackCategory::Data,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "JavaScript prototype pollution detected".into(),
                });
            }
        }
        None
    }
}
