use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // Credit card PAN
        Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap(),
        // AWS Access Key
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        // Private keys and certificates
        Regex::new(r"-----BEGIN\s*(?:RSA\s*)?PRIVATE\s*KEY").unwrap(),
        Regex::new(r"-----BEGIN\s*CERTIFICATE").unwrap(),
        Regex::new(r"-----BEGIN\s*DSA\s*PRIVATE").unwrap(),
        Regex::new(r"-----BEGIN\s*EC\s*PRIVATE").unwrap(),
        Regex::new(r"-----BEGIN\s*PGP\s*PRIVATE").unwrap(),
        // OpenAI/LLM API keys
        Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
        // Database connection strings
        Regex::new(r"(?i)mongodb(?:\+srv)?://[^/\s]+").unwrap(),
        Regex::new(r"(?i)mysql://[^/\s]+").unwrap(),
        Regex::new(r"(?i)postgres(?:ql)?://[^/\s]+").unwrap(),
        Regex::new(r"(?i)redis://[^/\s]+").unwrap(),
        Regex::new(r"(?i)jdbc:[a-z]+://").unwrap(),
        // JWT token (three dot-separated base64url sections)
        Regex::new(r"(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
    ]
});

pub struct DataLeakDetector;

impl Detector for DataLeakDetector {
    fn name(&self) -> &'static str {
        "data_leak"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "data_leak".into(),
                    category: AttackCategory::File,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Sensitive data leak detected".into(),
                });
            }
        }
        None
    }
}
