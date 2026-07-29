use regex::Regex;
use std::sync::LazyLock;
use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)<script[\s/>]").unwrap(),
        Regex::new(r"(?i)on[a-z]+\s*=").unwrap(),
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        Regex::new(r"(?i)<svg[\s/>]").unwrap(),
        Regex::new(r"(?i)expression\s*\(").unwrap(),
        Regex::new(r"(?i)<iframe[\s/>]").unwrap(),
        Regex::new(r"(?i)<embed[\s/>]").unwrap(),
        Regex::new(r"(?i)<object[\s/>]").unwrap(),
        Regex::new(r"(?i)vbscript\s*:").unwrap(),
        Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
        Regex::new(r"(?i)<link[\s/>]").unwrap(),
        Regex::new(r"(?i)<meta[\s/>]").unwrap(),
        Regex::new(r"(?i)eval\s*\(").unwrap(),
        Regex::new(r"(?i)fromCharCode\s*\(").unwrap(),
        Regex::new(r"(?i)document\.cookie").unwrap(),
        Regex::new(r"(?i)document\.write\s*\(").unwrap(),
        Regex::new(r"(?i)window\.location").unwrap(),
    ]
});

pub struct XssDetector;

impl Detector for XssDetector {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "xss".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "XSS cross-site scripting detected".into(),
                });
            }
        }
        None
    }
}
