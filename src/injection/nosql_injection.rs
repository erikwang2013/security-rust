// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 10 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 10 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#""(?i:\$ne"\s*:)"#,
        r#"|'(?i:\$ne'\s*:)"#,
        r#"|"(?i:\$gt"\s*:)"#,
        r#"|"(?i:\$gte"\s*:)"#,
        r#"|"(?i:\$lt"\s*:)"#,
        r#"|"(?i:\$lte"\s*:)"#,
        r#"|"(?i:\$regex"\s*:)"#,
        r#"|"(?i:\$where"\s*:)"#,
        r#"|"(?i:\$or"\s*:)"#,
        // `$eq` / `$nin` 只有处在**键位置**（后面跟 `:`）才是查询操作符。
        // 裸词形在正常文档里满地都是：「用 `$eq` 判断相等、`$nin` 排除一组值」
        // 这类 MongoDB/Node 说明曾被判 Critical。与上面九条的形态保持一致，
        // 只是引号可选（JS 对象字面量里可以写 `{$nin: [...]}`）。
        r#"|(?i:["']?\$(?:eq|nin)["']?\s*:)"#,
        // 曾有 `\{\s*"\$gt"\s*:\s*""\s*\}`——永远匹配不到：凡是命中它的输入，
        // 上面第 3 条的 `"\$gt"\s*:` 都已经先命中（find 取第一条命中的模式）。
    ))
    .unwrap()
});

pub struct NoSqlInjectionDetector;

impl Detector for NoSqlInjectionDetector {
    fn name(&self) -> &'static str {
        "nosql_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "NoSQL injection detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> NoSqlInjectionDetector {
        NoSqlInjectionDetector
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
    fn name_is_nosql_injection() {
        assert_eq!(det().name(), "nosql_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            r#"{"username": {"$ne": ""}}"#,
            r#"{"$gt": ""}"#,
            r#"{"user": {"$regex": "^admin"}}"#,
            r#"{"$or": [{"role": "admin"}]}"#,
            r#"{'$ne': ''}"#,
            r#"{"pass": {"$nin": ["a"]}}"#,
            r#"db.users.find({"$where": "sleep(5000)"})"#,
        ] {
            assert_hit(input);
        }
    }

    /// 删掉那条死模式后，认证绕过形态仍必须由 `"$gt"\s*:` 命中（README 承诺的行为）。
    #[test]
    fn gt_authentication_bypass_still_caught_by_operator_pattern() {
        let r = det().detect(r#"{"$gt": ""}"#).expect("应该命中");
        assert_eq!(r.matched_pattern, r#""$gt":"#);
        assert_eq!(r.offset, 1);
        // 空格变体同理
        assert!(det().detect(r#"{ "$gt" : "" }"#).is_some());
    }

    /// `$eq` / `$nin` 收紧后：键位置（带 `:`）仍报，文档里提到操作符名不报。
    #[test]
    fn eq_and_nin_require_key_position() {
        for input in [
            r#"{"$eq": 1}"#,
            r#"{"pass": {"$nin": ["a"]}}"#,
            r#"{$nin: [1, 2]}"#, // JS 对象字面量：引号可选
            r#"{ "$eq" : "x" }"#,
        ] {
            assert_hit(input);
        }
        for input in [
            "Use `$eq` for equality and `$nin` to exclude a set of values.",
            "The $eq operator matches documents where the field equals the value.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    /// 真实语料：普通 JSON、账单散文、文档里的裸操作符名都不该报。
    #[test]
    fn ignores_realistic_json_and_prose() {
        for input in [
            r#"{"user": "dana", "roles": ["admin", "dev"], "active": true}"#,
            r#"{"count": 42, "tags": {"a": 1, "b": 2}, "note": "hello"}"#,
            "MongoDB 文档：用 $where / $regex 之前先看查询计划，别直接拼字符串",
            "The invoice total is $250 and the tax is $19.99.",
            "SELECT * FROM users WHERE age > 18 ORDER BY name",
            "{\"a\": {\"b\": {\"c\": 1}}}",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            r#"{"name": "John", "age": 30, "city": "New York"}"#,
            r#"{"price": "$5.99"}"#,
            "The total cost is $100 and the discount is 10%",
            "The equation is simple to solve",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect("  \t ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: operator without colon or without dollar sign
        assert!(det().detect(r#"{"$ne"}"#).is_none());
        assert!(det().detect(r#"{"ne": ""}"#).is_none());
        assert!(det().detect("age > 18").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [r#"{"$NE": ""}"#, r#"{"$GTE": 5}"#, r#"{"$REGEX": "^a"}"#] {
            assert_hit(input);
        }
    }
}
