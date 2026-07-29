use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)//[^/]+\.[a-z]{2,}").unwrap(),
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
        Regex::new(r"(?i)data\s*:\s*text/plain").unwrap(),
    ]
});

pub struct OpenRedirectDetector;

impl Detector for OpenRedirectDetector {
    fn name(&self) -> &'static str {
        "open_redirect"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "open_redirect".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Open redirect detected".into(),
                });
            }
        }
        None
    }
}
