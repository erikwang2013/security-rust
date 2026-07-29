use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)<\?php").unwrap(),
        Regex::new(r"(?i)<\?=").unwrap(),
        Regex::new(r"(?i)<%\s*@").unwrap(),
        Regex::new(r"(?i)<%\s*=").unwrap(),
        Regex::new(r#"(?i)<script\s+language\s*=\s*["']?(?:php|vbscript|jscript)["']?"#).unwrap(),
        Regex::new(r"(?i)eval\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)system\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)exec\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)passthru\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)shell_exec\s*\(\s*\$").unwrap(),
        Regex::new(r"(?i)\$_GET\[").unwrap(),
        Regex::new(r"(?i)\$_POST\[").unwrap(),
        Regex::new(r"(?i)\$_REQUEST\[").unwrap(),
        Regex::new(r"(?i)\$_SERVER\[").unwrap(),
        Regex::new(r"(?i)base64_decode\s*\(").unwrap(),
    ]
});

pub struct UploadDetector;

impl Detector for UploadDetector {
    fn name(&self) -> &'static str {
        "upload"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "upload".into(),
                    category: AttackCategory::File,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Malicious file upload detected".into(),
                });
            }
        }
        None
    }
}
