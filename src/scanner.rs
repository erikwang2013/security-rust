// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::data::{
    CsvInjectionDetector, DeserializationDetector, JwtAttackDetector, MailHeaderDetector,
    PrototypePollutionDetector,
};
use crate::file::{DataLeakDetector, PathTraversalDetector, UploadDetector};
use crate::injection::{
    CommandInjectionDetector, GraphQlInjectionDetector, JndiInjectionDetector,
    LdapInjectionDetector, NoSqlInjectionDetector, SqlInjectionDetector, SsiInjectionDetector,
    SstiDetector, XPathInjectionDetector, XssDetector,
};
use crate::protocol::{
    CorsDetector, DnsRebindingDetector, HeaderInjectionDetector, HostHeaderDetector,
    OpenRedirectDetector, RequestSmugglingDetector, SsrfDetector, WebSocketDetector, XxeDetector,
};
use crate::{Detector, result::DetectionResult};

pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            detectors: vec![
                // Injection
                Box::new(XssDetector),
                Box::new(SqlInjectionDetector),
                Box::new(CommandInjectionDetector),
                Box::new(NoSqlInjectionDetector),
                Box::new(LdapInjectionDetector),
                Box::new(XPathInjectionDetector),
                Box::new(JndiInjectionDetector),
                Box::new(SsiInjectionDetector),
                Box::new(GraphQlInjectionDetector),
                Box::new(SstiDetector),
                // Protocol
                Box::new(SsrfDetector),
                Box::new(XxeDetector),
                Box::new(HeaderInjectionDetector),
                Box::new(HostHeaderDetector),
                Box::new(RequestSmugglingDetector),
                Box::new(OpenRedirectDetector),
                Box::new(CorsDetector),
                Box::new(WebSocketDetector),
                Box::new(DnsRebindingDetector),
                // Data
                Box::new(DeserializationDetector),
                Box::new(CsvInjectionDetector),
                Box::new(MailHeaderDetector),
                Box::new(JwtAttackDetector),
                Box::new(PrototypePollutionDetector),
                // File
                Box::new(PathTraversalDetector),
                Box::new(UploadDetector),
                Box::new(DataLeakDetector),
            ],
        }
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    pub fn scan(&self, input: &str) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for detector in &self.detectors {
            if let Some(result) = detector.detect(input) {
                results.push(result);
            }
        }
        results
    }

    pub fn scan_with(&self, input: &str, names: &[&str]) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for detector in &self.detectors {
            if names.contains(&detector.name())
                && let Some(result) = detector.detect(input)
            {
                results.push(result);
            }
        }
        results
    }
}

#[derive(Default)]
pub struct ScannerBuilder {
    detectors: Vec<Box<dyn Detector>>,
}

impl ScannerBuilder {
    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    pub fn build(self) -> Scanner {
        Scanner {
            detectors: self.detectors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackCategory, Severity};

    const XSS: &str = "<script>alert(1)</script>";

    fn types(results: &[DetectionResult]) -> Vec<&str> {
        results.iter().map(|r| r.attack_type.as_str()).collect()
    }

    #[test]
    fn default_scanner_registers_all_27_detectors() {
        assert_eq!(Scanner::default().detectors.len(), 27);
    }

    #[test]
    fn scan_detects_known_attack() {
        let results = Scanner::default().scan(XSS);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].attack_type, "xss");
        assert_eq!(results[0].category, AttackCategory::Injection);
        assert_eq!(results[0].severity, Severity::Critical);
    }

    #[test]
    fn scan_returns_empty_for_clean_input() {
        for input in [
            "hello world 123",
            "q=2024--2025",
            "q=donation=5",
            "穿越之霸道总裁爱上我--重生之都市修仙",
        ] {
            assert!(
                Scanner::default().scan(input).is_empty(),
                "false positive: {input}"
            );
        }
    }

    #[test]
    fn scan_returns_empty_for_empty_string() {
        assert!(Scanner::default().scan("").is_empty());
    }

    #[test]
    fn scan_with_filters_by_detector_name() {
        let scanner = Scanner::default();
        assert_eq!(scanner.scan_with(XSS, &["xss"]).len(), 1);
        assert!(scanner.scan_with(XSS, &["sql_injection"]).is_empty());
        assert!(scanner.scan_with(XSS, &["unknown"]).is_empty());
    }

    #[test]
    fn scan_with_multiple_names() {
        let input = "1 UNION SELECT password FROM users; <script>alert(1)</script>";
        let results = Scanner::default().scan_with(input, &["sql_injection", "xss"]);
        let t = types(&results);
        assert!(t.contains(&"sql_injection") && t.contains(&"xss"));
    }

    #[test]
    fn new_matches_default() {
        assert_eq!(
            Scanner::new().detectors.len(),
            Scanner::default().detectors.len()
        );
    }

    #[test]
    fn builder_without_detectors_scans_nothing() {
        assert!(Scanner::builder().build().scan(XSS).is_empty());
    }

    #[test]
    fn builder_with_custom_detector() {
        let scanner = Scanner::builder()
            .with_detector(Box::new(crate::injection::XssDetector))
            .build();
        let results = scanner.scan(XSS);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].attack_type, "xss");
    }

    #[test]
    fn detection_result_has_pattern_offset_and_message() {
        let results = Scanner::default().scan(XSS);
        let r = &results[0];
        assert!(!r.matched_pattern.is_empty());
        assert!(r.offset <= XSS.len());
        assert!(!r.message.is_empty());
    }

    #[test]
    fn scan_is_deterministic() {
        let input = "SELECT 1; <script>alert(1)</script>";
        assert_eq!(
            Scanner::default().scan(input),
            Scanner::default().scan(input)
        );
    }
}
