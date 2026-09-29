// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：内省字段处在**查询形态**里 —— 带选择集（`__schema {`）。
/// 散文/文档里提到 `__schema`（「内省查询用 `__schema` 和 `__type`」）不报。
/// 2 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 2 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 各分支共同的 `(?i)` 提升为外层 `(?i:…)`，作用域正好覆盖全部 2 条分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i:__schema\s*\{",
        r"|__type\s*\{)",
    ))
    .unwrap()
});

/// 弱信号：`__typename` 由 Apollo/Relay 客户端自动加进每条查询，是正常前端代码的
/// 固定内容；5 层花括号与深层 JSON 配置形状完全相同。单条不拒绝。
/// 2 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 2 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i:__typename)",
        r"|\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{",
    ))
    .unwrap()
});

pub struct GraphQlInjectionDetector;

impl Detector for GraphQlInjectionDetector {
    fn name(&self) -> &'static str {
        "graphql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Medium,
            "GraphQL injection/introspection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "GraphQL introspection field / nesting present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> GraphQlInjectionDetector {
        GraphQlInjectionDetector
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(&det(), input, AttackCategory::Injection, severity);
    }

    #[test]
    fn name_is_graphql_injection() {
        assert_eq!(det().name(), "graphql_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for (input, severity) in [
            // 强信号：内省字段带选择集，Medium
            ("{ __schema { types { name } } }", Severity::Medium),
            ("query { __type { name } }", Severity::Medium),
            ("fragment F on __Type { name }", Severity::Medium),
            // 弱信号：客户端固定字段与深层嵌套，Low
            ("query { __typename }", Severity::Low),
            ("{a{b{c{d{e{f}}}}}}", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }

    /// 正常内容：Apollo 客户端会自动把 `__typename` 加进每条查询，5 层对象嵌套
    /// 是配置 JSON 的常态。两者曾分别被判 Medium —— 叠加其它模块即可越过拒绝线。
    #[test]
    fn client_code_and_nested_json_are_not_high() {
        for (input, severity) in [
            ("const key = data.__typename + \":\" + data.id;", Severity::Low),
            (
                r#"{"response": {"data": {"user": {"profile": {"name": "Ada"}}}}}"#,
                Severity::Low,
            ),
            ("Apollo adds `__typename` to every selection set automatically.", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "query { user(id: 1) { name } }",
            r#"{"a": {"b": {"c": {"d": 1}}}}"#,
            "The schema was updated today",
            // 文档在讨论内省，不是内省查询：没有选择集
            "Introspection queries use `__schema` and `__type`; disable them in production.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: not quite the introspection keyword, or not deep enough
        assert!(det().detect("{__schem}").is_none());
        assert!(det().detect("schema").is_none());
        assert!(det().detect("{{{{").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for (input, severity) in [
            ("{ __SCHEMA { types } }", Severity::Medium),
            ("__Type { name }", Severity::Medium),
            ("__TYPENAME", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }
}
