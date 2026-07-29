use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"\.\./").unwrap(),
        Regex::new(r"\.\.\\").unwrap(),
        Regex::new(r"(?i)\.\.%2[Ff]").unwrap(),
        Regex::new(r"(?i)%2[Ee]%2[Ee]").unwrap(),
        Regex::new(r"(?i)php://filter").unwrap(),
        Regex::new(r"(?i)php://input").unwrap(),
        Regex::new(r"(?i)data://").unwrap(),
        Regex::new(r"(?i)expect://").unwrap(),
        Regex::new(r"(?i)phar://").unwrap(),
        Regex::new(r"(?i)zip://").unwrap(),
        Regex::new(r"(?i)glob://").unwrap(),
        Regex::new(r"%00").unwrap(),
        Regex::new(r"\x00").unwrap(),
    ]
});

pub struct PathTraversalDetector;

impl Detector for PathTraversalDetector {
    fn name(&self) -> &'static str {
        "path_traversal"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "path_traversal".into(),
                    category: AttackCategory::File,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Path traversal attack detected".into(),
                });
            }
        }
        None
    }
}
