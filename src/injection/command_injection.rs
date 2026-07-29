use crate::{AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"`[^`]+`").unwrap(),
        Regex::new(r"\$\([^)]+\)").unwrap(),
        Regex::new(r"\|[\s]*\w+").unwrap(),
        Regex::new(r"\|\|[\s]*\w+").unwrap(),
        Regex::new(r"&&\s*\w+").unwrap(),
        Regex::new(r"/dev/tcp[/\w]*").unwrap(),
        Regex::new(r"(?i)passthru\s*\(").unwrap(),
        Regex::new(r"(?i)shell_exec\s*\(").unwrap(),
        Regex::new(r"(?i)system\s*\(").unwrap(),
        Regex::new(r"(?i)exec\s*\(").unwrap(),
        Regex::new(r"(?i)popen\s*\(").unwrap(),
        Regex::new(r"(?i)pcntl_exec\s*\(").unwrap(),
        Regex::new(r"(?i)cmd\.exe").unwrap(),
        Regex::new(r"(?i)powershell").unwrap(),
        Regex::new(r">/dev/null").unwrap(),
    ]
});

pub struct CommandInjectionDetector;

impl Detector for CommandInjectionDetector {
    fn name(&self) -> &'static str {
        "command_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for re in PATTERNS.iter() {
            if let Some(m) = re.find(input) {
                return Some(DetectionResult {
                    attack_type: "command_injection".into(),
                    category: AttackCategory::Injection,
                    severity: Severity::Critical,
                    matched_pattern: m.as_str().to_string(),
                    offset: m.start(),
                    message: "Command injection detected".into(),
                });
            }
        }
        None
    }
}
