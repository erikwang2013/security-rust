// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 防御方视角：调用方准备把用户输入当正则编译时先扫一遍。
// 只挑无歧义会指数回溯的形态，宁可漏也不误杀。
// ponytail: 只做单层括号，`((a+))+` 这类深嵌套漏检——要覆盖得住上括号配对分析
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // (a+)+ / (a*)* / (.+)+ / (\w+\s?)*：量词套量词
        Regex::new(r"\([^()]{1,60}[+*?]\)[+*]").unwrap(),
        // (a+){2,}：量词套有界重复
        Regex::new(r"\([^()]{1,60}[+*?]\)\{\d+,\}").unwrap(),
        // (a{2,})* / (a{2,}){3,}：{n,} 套外层量词
        Regex::new(r"\([^()]{1,60}\{\d+,\}\)[+*]").unwrap(),
        Regex::new(r"\([^()]{1,60}\{\d+,\}\)\{\d+,\}").unwrap(),
        // (a|a)* / (.|x)+ / (\w|y)*：分支只有单字符或字符类，必然重叠
        Regex::new(r"\((?:\\.|[^()\\|]{1})?\|[^()]{0,60}\)[+*]").unwrap(),
        Regex::new(r"\((?:\\.|[^()\\|]{1})?\|[^()]{0,60}\)\{\d+,\}").unwrap(),
    ]
});

pub struct ReDoSDetector;

impl Detector for ReDoSDetector {
    fn name(&self) -> &'static str {
        "redos"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Data, Severity::Medium, "Catastrophic backtracking pattern detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> ReDoSDetector {
        ReDoSDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Data, Severity::Medium);
    }

    #[test]
    fn name_is_redos() {
        assert_eq!(det().name(), "redos");
    }

    #[test]
    fn detects_nested_quantifiers() {
        for input in [
            "(a+)+",
            "(a*)*",
            "(.+)+",
            "([a-z]*)+",
            "(\\d+)+$",
            "^([a-zA-Z]+)*$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_nested_bounded_repeats() {
        for input in [
            "(a+){2,}",
            "(a{2,})*",
            "(a{2,}){3,}",
            "(\\d{1,}){1,}",
            "^(a{3,})+$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_overlapping_alternation() {
        for input in [
            "(a|a)*",
            "(.|x)+",
            "(\\w|y)*",
            "(x|)*",
            "(a|a){1,}",
            "^(a|b|.)*$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_in_longer_expression() {
        for input in [
            r"^\s*(a+)+$",
            r"^(\w+\s?)*$",
            r"^([a-z]+)*$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn ignores_safe_regexes() {
        for input in [
            r"^\d{4}-\d{2}-\d{2}$",
            r"^[a-z]+$",
            r"(GET|POST)",
            r"(GET|POST)*",
            r"(foo|bar)*",
            r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$",
            r"\(escaped\)+",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "5*(3+2)",
            "the (very) long text",
            "function(a, b)",
            "穿越之霸道总裁爱上我--重生之都市修仙",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "()");
        assert_clean(&det(), "()*");
        assert_clean(&det(), "(a)");
        // 量词在括号外但组内无重复——(really)* 是安全的
        assert_clean(&det(), "(really)*");
        // 已知缺口：深嵌套括号 + 长分支重叠看不到，单层括号启发式的上限
        assert_clean(&det(), r"^(([a-z])+.)+[A-Z]([a-z])+$");
        assert_clean(&det(), "^([0-9]|[0-9]){1,}$");
    }
}
