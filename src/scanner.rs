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

/// 检测器集合：按注册顺序对同一输入逐个运行。
///
/// ## 两套装配语义
///
/// [`Scanner::default()`] / [`Scanner::new()`] 一键装配全部 32 个检测器，零配置可用；
/// [`Scanner::builder()`] 则**从空表起步** —— 忘了 `.with_detector()` 也能 `build()`
/// 成功，得到一个什么都不检的 scanner，`scan()` 恒返回空且不报错。自定义装配后
/// 用 [`Scanner::detector_names`] 自检注册结果（失败是静默的，这是最容易踩的坑）。
///
/// ## `scan` 与 `scan_with`
///
/// - [`scan`](Self::scan) 跑全部检测器；[`scan_with`](Self::scan_with) 只跑名字在
///   名单里的那些。名单里的**未知名字静默跳过、不报错**（`scan_with(x, &["typo"])`
///   恒为空），重复名字也不会让检测器跑两遍 —— 调用方可以放心用一份跨版本共享的
///   名单，不必逐个做存在性检查。
/// - 两者对同一输入**每个检测器至多产出一条**结果（有强弱两档的先试强档）。
/// - 结果顺序 = 注册顺序，同一输入任意次扫描结果完全一致（无状态、确定性）。
///
/// ## 只报告，不拦截
///
/// 库自身不做任何拒绝动作：拒绝线（如 `risk.level >= RiskLevel::High`）由调用方定，
/// 参考 `examples/waf.rs`。
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
    /// 等价于 [`Scanner::default()`]：装配全部 32 个检测器。空表起步请走
    /// [`Scanner::builder()`]。
    pub fn new() -> Self {
        Self::default()
    }

    /// 自定义装配的起点，**空表**、不含任何检测器（与 `default()` 不同）。
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    /// 用全部检测器扫描 `input`，返回全部命中（顺序 = 注册顺序）。
    ///
    /// 输入干净或为空串时返回空 `Vec` —— 没有错误通道，检测器不产生"扫描失败"这种状态。
    /// 有强弱两档的检测器先试强档，故**每个 `attack_type` 至多出现一次**；弱信号
    /// 也在结果里（`severity == Severity::Low`），不会静默漏报。
    ///
    /// 判"要不要拒绝这条输入"别只看结果非空 —— 单条弱信号不足以越过拒绝线，用
    /// [`Scanner::assess`] 看聚合分。
    // 丢掉扫描结果 = 静默放行：命中被算出来又没人看，等于 WAF 没装。
    #[must_use]
    pub fn scan(&self, input: &str) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for detector in &self.detectors {
            if let Some(result) = detector.detect(input) {
                results.push(result);
            }
        }
        results
    }

    /// 把「有/无命中」升级为「累积风险」：内部就是 `scan` + [`score::assess`]，
    /// 多条低危叠加可升到更高等级。
    ///
    /// 返回的 [`RiskAssessment`] 带三项：`level`（聚合等级）、`score`（权重和）、
    /// `results`（参与聚合的命中条数）。拒绝线看 `level` 而不是"有无命中"：
    /// 单条弱信号（Low，5 分）够不到 `RiskLevel::High`（40 分），而多条弱信号叠加
    /// 会升级 —— 这正是弱信号档存在的意义（见 [`DetectionResult::severity`]）。
    #[must_use]
    pub fn assess(&self, input: &str) -> RiskAssessment {
        score::assess(&self.scan(input))
    }

    /// 只跑名字出现在 `names` 里的检测器，其余完全跳过。
    ///
    /// `names` 里的**未知名字静默忽略**（不报错、不告警）：`scan_with(x, &["typo"])`
    /// 返回空 `Vec` 而不是失败；重复的名字不会让同一检测器跑两遍。语义上等价于
    /// `scan(input)` 再按 `attack_type ∈ names` 过滤（`tests/invariants.rs` 对 32 个
    /// 名字逐一核验这条等价性），但省掉了不相关检测器的正则开销。
    ///
    /// 空名单 ⇒ 恒返回空 `Vec`。
    #[must_use]
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

    /// 按注册顺序列出全部检测器名字。
    ///
    /// 用途是自检：`Scanner::builder()` 从空表起步，装完可以先看这里确认装上了什么；
    /// 也可以拿它给 [`Scanner::scan_with`] 拼名单。名字即
    /// [`Detector::name`] 的返回值，同时是 [`DetectionResult::attack_type`] 的取值。
    ///
    /// 返回 `impl Iterator<Item = &'static str> + '_`：名字本身是 `'static` 字面量，
    /// 迭代器只在借用 `self` 期间有效；收集成 `Vec<&'static str>` 即可脱离 scanner 保存。
    pub fn detector_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.detectors.iter().map(|d| d.name())
    }
}

/// [`Scanner`] 的自定义装配器。用 [`Scanner::builder()`] 构造。
///
/// **从空表起步**：与 `Scanner::default()` 的 32 个检测器无关，装多少就是多少；
/// 一个都不装也能 `build()` 成功，得到的 scanner 恒返回空结果 —— 这是行为不是错误，
/// 自检用 [`Scanner::detector_names`]。
#[derive(Default)]
pub struct ScannerBuilder {
    detectors: Vec<Box<dyn Detector>>,
}

impl ScannerBuilder {
    /// 追加一个检测器（按调用顺序注册，也决定 `scan()` 的结果顺序）。
    ///
    /// 同一个检测器注册两次不报错，`scan()` 里就会跑两遍、产出两条结果 ——
    /// 名字不用于去重（32 个内置检测器名字唯一，由 `tests/invariants.rs` 钉住）。
    #[must_use]
    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// 产出 scanner。不会失败，也不会补默认检测器（空表就是空 scanner）。
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
