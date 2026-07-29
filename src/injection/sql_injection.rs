use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)UNION\s+(?:ALL\s+)?SELECT").unwrap(),
        Regex::new(r"(?i)SELECT\s+.*\s+FROM\s+").unwrap(),
        Regex::new(r"(?i)/\*!.*?\*/").unwrap(),
        Regex::new(r"(?i)sleep\s*\(").unwrap(),
        Regex::new(r"(?i)benchmark\s*\(").unwrap(),
        Regex::new(r"(?i)pg_sleep\s*\(").unwrap(),
        Regex::new(r"(?i)information_schema").unwrap(),
        Regex::new(r"(?i)exec\s+(?:sp_|xp_)").unwrap(),
        Regex::new(r"(?i)WAITFOR\s+DELAY").unwrap(),
        Regex::new(r"(?i)'\s*OR\s*'1'\s*=\s*'1").unwrap(),
        Regex::new(r"(?i)'\s*OR\s*1\s*=\s*1\s*--").unwrap(),
        Regex::new(r"(?i)LOAD_FILE\s*\(").unwrap(),
        Regex::new(r"(?i)INTO\s+(?:OUT|DUMP)FILE").unwrap(),
        Regex::new(r"(?i)OUTFILE\s+").unwrap(),
        Regex::new(r"(?i)SELECT\s+\*").unwrap(),
        Regex::new(r"(?i)DROP\s+TABLE").unwrap(),
        Regex::new(r"(?i)INSERT\s+INTO").unwrap(),
    ]
});

pub struct SqlInjectionDetector;

impl Detector for SqlInjectionDetector {
    fn name(&self) -> &'static str {
        "sql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "sql_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "SQL injection detected".into(),
                });
            }
        }
        None
    }
}
