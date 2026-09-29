// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::data::{
    CsvInjectionDetector, DeserializationDetector, FormulaInjectionDetector, JwtAttackDetector,
    MailHeaderDetector, PrototypePollutionDetector, ReDoSDetector,
};
use crate::file::{DataLeakDetector, PathTraversalDetector, UploadDetector};
use crate::injection::{
    CommandInjectionDetector, FormatStringDetector, GraphQlInjectionDetector,
    JndiInjectionDetector, LdapInjectionDetector, NoSqlInjectionDetector, SqlInjectionDetector,
    SsiInjectionDetector, SstiDetector, XPathInjectionDetector, XssDetector,
};
use crate::protocol::{
    CorsDetector, DnsRebindingDetector, HeaderInjectionDetector, HostHeaderDetector,
    HttpParameterPollutionDetector, Log4ShellDetector, OpenRedirectDetector,
    RequestSmugglingDetector, SsrfDetector, WebSocketDetector, XxeDetector,
};
use crate::score::{self, RiskAssessment};
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
                Box::new(FormatStringDetector),
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
                Box::new(Log4ShellDetector),
                Box::new(HttpParameterPollutionDetector),
                // Data
                Box::new(DeserializationDetector),
                Box::new(CsvInjectionDetector),
                Box::new(MailHeaderDetector),
                Box::new(JwtAttackDetector),
                Box::new(PrototypePollutionDetector),
                Box::new(FormulaInjectionDetector),
                Box::new(ReDoSDetector),
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

    /// 把「有/无命中」升级为「累积风险」：多条低危叠加可升到更高等级。
    pub fn assess(&self, input: &str) -> RiskAssessment {
        score::assess(&self.scan(input))
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

    /// 弱信号载荷：`<script>` 的存在本身在正常网页里极常见，故判 Low。
    const XSS: &str = "<script>alert(1)</script>";

    /// 强信号载荷：事件处理器是攻击者可控的可执行形态，判 Critical。
    /// 需要走 Critical 路径的测试用这个，别把 `XSS` 改判 —— 那会让测试名说谎。
    const XSS_CRITICAL: &str = "<img src=x onerror=alert(1)>";

    fn types(results: &[DetectionResult]) -> Vec<&str> {
        results.iter().map(|r| r.attack_type.as_str()).collect()
    }

    #[test]
    fn default_scanner_registers_all_32_detectors() {
        assert_eq!(Scanner::default().detectors.len(), 32);
    }

    #[test]
    fn default_scanner_registers_each_detector_once() {
        let scanner = Scanner::default();
        let mut names: Vec<&str> = scanner.detectors.iter().map(|d| d.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "检测器名字重复: {names:?}");
    }

    #[test]
    fn new_detectors_are_registered() {
        let scanner = Scanner::default();
        let names: Vec<&str> = scanner.detectors.iter().map(|d| d.name()).collect();
        for expected in [
            "log4shell",
            "hpp",
            "formula_injection",
            "redos",
            "format_string",
        ] {
            assert!(names.contains(&expected), "缺少检测器: {expected}");
        }
    }

    /// 只覆盖新增的这几个检测器，不代表整个 scanner 对干净输入全静默
    /// ——粗粒度层（csv_injection 认行首 `=+-@`、ssti 认 `${`）本来就会命中，
    /// 判定"整机干净"要看 assess 的评分，别拿这个测试当整机基线。
    #[test]
    fn new_detectors_only_do_not_fire_on_clean_input() {
        let scanner = Scanner::default();
        for input in [
            "the price is ${amount}",
            "a=1&b=2",
            "= 5",
            "-3 度",
            "a@b.com",
            "100% safe",
            "50% off",
            "line one\r\nline two",
            "5*(3+2)",
        ] {
            let results = scanner.scan_with(
                input,
                &[
                    "log4shell",
                    "hpp",
                    "formula_injection",
                    "redos",
                    "format_string",
                ],
            );
            assert!(
                results.is_empty(),
                "新检测器误报 {input:?}: {:?}",
                types(&results)
            );
        }
    }

    #[test]
    fn assess_returns_none_for_clean_input() {
        let a = Scanner::default().assess("hello world 123");
        assert_eq!(a.level, crate::score::RiskLevel::None);
        assert_eq!(a.score, 0);
        assert_eq!(a.results, 0);
    }

    #[test]
    fn assess_returns_critical_for_critical_hit() {
        let a = Scanner::default().assess(XSS_CRITICAL);
        assert_eq!(a.level, crate::score::RiskLevel::Critical);
        assert_eq!(a.results, 1);
        assert!(a.score > 0);
    }

    /// 分档契约：标签「存在」是弱信号，报 Low 且不足以触发拒绝；
    /// 事件处理器是强信号，报 Critical 且直接拒绝。
    /// 这条钉住的是「正常网页不该被拒」这个产品行为。
    #[test]
    fn tag_presence_is_low_while_event_handler_is_critical() {
        let scanner = Scanner::default();

        let weak = scanner.scan(XSS);
        assert_eq!(weak.len(), 1);
        assert_eq!(weak[0].attack_type, "xss");
        assert_eq!(weak[0].severity, Severity::Low);
        assert!(
            scanner.assess(XSS).level < crate::score::RiskLevel::High,
            "标签存在不得单独越线"
        );

        let strong = scanner.scan(XSS_CRITICAL);
        assert_eq!(strong[0].severity, Severity::Critical);
        assert_eq!(
            scanner.assess(XSS_CRITICAL).level,
            crate::score::RiskLevel::Critical
        );
    }

    #[test]
    fn assess_escalates_on_stacked_medium_hits() {
        let input = "=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd";
        let a = Scanner::default().assess(input);
        assert!(a.results >= 3, "期望多条命中，实际 {:?}", a);
        assert!(
            a.level >= crate::score::RiskLevel::High,
            "叠加后应升级: {:?}",
            a
        );
    }

    #[test]
    fn scan_detects_known_attack() {
        let results = Scanner::default().scan(XSS_CRITICAL);
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
