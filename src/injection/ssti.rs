use crate::{AttackCategory, DetectionResult, Detector, Severity};
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
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "ssti".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Server-Side Template Injection detected".into(),
                });
            }
        }
        None
    }
}
