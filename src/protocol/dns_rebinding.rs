use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)Host:\s*127\.").unwrap(),
        Regex::new(r"(?i)Host:\s*10\.").unwrap(),
        Regex::new(r"(?i)Host:\s*192\.168\.").unwrap(),
        Regex::new(r"(?i)Host:\s*172\.(1[6-9]|2\d|3[01])").unwrap(),
        Regex::new(r"(?i)Host:\s*localhost").unwrap(),
        Regex::new(r"(?i)Host:\s*\[::1\]").unwrap(),
        Regex::new(r"(?i)Host:\s*0\.0\.0\.0").unwrap(),
    ]
});

pub struct DnsRebindingDetector;

impl Detector for DnsRebindingDetector {
    fn name(&self) -> &'static str {
        "dns_rebinding"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "dns_rebinding".into(),
                    category: AttackCategory::Protocol,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "DNS rebinding attack detected".into(),
                });
            }
        }
        None
    }
}
