// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：引号开头的布尔恒等式，以及带路径的联合查询 —— 都是受约束的攻击形态。
/// 7 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 7 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"'(?i:\s*or\s*'1'\s*=\s*'1)",
        r"|'(?i:\s*and\s*'1'\s*=\s*'2)",
        r"|'(?i:\s*or\s*1\s*=\s*1)",
        r#"|"(?i:\s*or\s*"1"\s*=\s*"1)"#,
        // 联合查询：XPath 的 `|` 两侧都是节点集（以 `/`、`@`、`(` 或 `*` 开头）。
        // 旧形态 `'\s*\]\s*\|\s*` 只认「`']` 后面有 `|`」，于是命中了 JS 的按位或
        // 与 Python 的集合并 —— `opts['flags'] | 0`、`merged = d['a'] | d['b']`
        // 都是正常代码，且判 High（单条即拒绝）。
        r"|'\s*\]\s*\|\s*[/@(*]",
        r"|'(?i:\s*or\s*''=')",
        r"|'(?i:\s*or\s*true\s*\()",
    ))
    .unwrap()
});

pub struct XPathInjectionDetector;

impl Detector for XPathInjectionDetector {
    fn name(&self) -> &'static str {
        "xpath_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::High,
            "XPATH injection detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> XPathInjectionDetector {
        XPathInjectionDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::High,
        );
    }

    #[test]
    fn name_is_xpath_injection() {
        assert_eq!(det().name(), "xpath_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "' or '1'='1",
            "' or 1=1",
            "' and '1'='2",
            r#"" or "1"="1"#,
            "' or ''='",
            "' or true()",
            "']|//admin",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The first quarter results are in",
            "or is a conjunction in English",
            "I want 1 pizza and 1 drink",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: quote missing or condition not satisfied
        assert!(det().detect("or 1=1").is_none());
        assert!(det().detect("' or '2'='1").is_none());
        assert!(det().detect("' or 2=2").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in ["' OR '1'='1", "' And '1'='2", r#"" Or "1"="1"#] {
            assert_hit(input);
        }
    }

    /// 反向对照：`']` 后面跟 `|` 在正常代码里是按位或 / 集合并 —— 收紧前
    /// `'\s*\]\s*\|\s*` 把这三条都判 High（单条即拒绝）。
    #[test]
    fn bracket_index_bitwise_or_is_not_detected() {
        for input in [
            "const flags = opts['flags'] | 0;\n",
            "merged = d['a'] | d['b']\n",
            "type Mode = flags['mode'] | Extra;\n",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    /// 收紧的另一半：联合查询的节点集形态必须照报。
    #[test]
    fn union_with_path_still_detected() {
        for input in [
            "']|//admin",
            "'] | /user[position()=1]",
            "']|@secret-attr",
            "']|*",
        ] {
            assert_hit(input);
        }
    }
}
