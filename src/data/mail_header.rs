use regex::Regex;
use std::sync::LazyLock;
use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Bcc\s*:").unwrap(),
        Regex::new(r"(?i)Cc\s*:").unwrap(),
        Regex::new(r"(?i)From\s*:.*\r?\n.*From\s*:").unwrap(),
        Regex::new(r"(?i)MIME-Version\s*:").unwrap(),
        Regex::new(r"(?i)Content-Type\s*:.*multipart").unwrap(),
        Regex::new(r"(?i)boundary\s*=").unwrap(),
    ]
});

pub struct MailHeaderDetector;

impl Detector for MailHeaderDetector {
    fn name(&self) -> &'static str {
        "mail_header"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "mail_header".into(),
                    category: AttackCategory::Data,
                    severity: Severity::Medium,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Mail header injection detected".into(),
                });
            }
        }
        None
    }
}
