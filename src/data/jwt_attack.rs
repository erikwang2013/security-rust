use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"(?i)"alg"\s*:\s*"none""#).unwrap(),
        Regex::new(r#"(?i)"alg"\s*:\s*"None""#).unwrap(),
        Regex::new(r#"(?i)"alg"\s*:\s*"NONE""#).unwrap(),
        Regex::new(r#"(?i)"kid"\s*:.*\.\.\/"#).unwrap(),
        Regex::new(r#"(?i)"kid"\s*:.*\.\.\\"#).unwrap(),
        Regex::new(r#"(?i)"kid"\s*:.*/dev/null"#).unwrap(),
        Regex::new(r"ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[\s]*").unwrap(),
        Regex::new(r"ey[A-Za-z0-9_-]+\.[\s]*\.[A-Za-z0-9_-]+").unwrap(),
    ]
});

pub struct JwtAttackDetector;

impl Detector for JwtAttackDetector {
    fn name(&self) -> &'static str {
        "jwt_attack"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "jwt_attack".into(),
                    category: AttackCategory::Data,
                    severity: Severity::High,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "JWT attack detected".into(),
                });
            }
        }
        None
    }
}
