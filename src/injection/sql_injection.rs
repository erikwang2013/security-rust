// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
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
        Regex::new(r"(?i)DROP\s+TABLE").unwrap(),
        Regex::new(r"(?i)INSERT\s+INTO").unwrap(),
        // `--` requires trailing space/EOL/`+` (MySQL URL-encoded space) so SSI's `"-->` stays clean
        Regex::new(r#"(?i)(?:'|"|\))\s*(?:(?:--(?:\s|$|\+))|#|/\*)"#).unwrap(),
        Regex::new(r"(?i)(?:/\*.*?\*/|--|#)\s*(?:or|and|union|select)\b").unwrap(),
    ]
});

pub struct SqlInjectionDetector;

impl Detector for SqlInjectionDetector {
    fn name(&self) -> &'static str {
        "sql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Injection, Severity::Critical, "SQL injection detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SqlInjectionDetector {
        SqlInjectionDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::Critical,
        );
    }

    #[test]
    fn name_is_sql_injection() {
        assert_eq!(det().name(), "sql_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "1 UNION SELECT password FROM users",
            "1; SELECT pg_sleep(5)",
            "admin' OR '1'='1",
            "SELECT * FROM users WHERE id=1",
            "id=1 /*!50000union select*/",
            "1; WAITFOR DELAY '0:0:5'",
            "username' OR 1=1 --",
            "admin'--",
            "1') --",
            "x'#comment",
            "-- or 1=1",
            "/*x*/ union select",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "Please choose an option below",
            "I will sleep well tonight",
            "The benchmark results look great",
            "Drop me a line when you arrive",
            "The information desk is on the second floor",
            "q=2024--2025",
            "q=donation=5",
            "穿越之霸道总裁爱上我--重生之都市修仙",
            "chapter 2024--2025 更新",
            "donation=5&q=test",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: keyword present but not the payload form
        assert!(det().detect("UNOIN SILE CT *").is_none());
        assert!(det().detect("select from users").is_none());
        assert!(det().detect("sleep 5").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "1 UnIoN SeLeCt password",
            "Sleep(5)",
            "1; SELECT Pg_Sleep(10)",
            "' or '1'='1",
        ] {
            assert_hit(input);
        }
    }
}
