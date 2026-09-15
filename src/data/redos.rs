// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 防御方视角：调用方准备把用户输入当正则编译时先扫一遍。
// 只挑无歧义会指数回溯的形态，宁可漏也不误杀。
// ponytail: 只做单层括号，`((a+))+` 这类深嵌套漏检——要覆盖得住上括号配对分析
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    // 外层量词：`*` / `+` / `{n,}` 都会让内层量词的回溯次数相乘
    const Q: &str = r"(?:[+*?]|\{\d+,\})";
    // 被重复的原子限定为可打印 ASCII：真实正则的原子是 ASCII，而 `价格 (元+)* 说明`
    // 这类中文正文里的括号星号是散文，不是正则。非 ASCII 原子一律放过。
    vec![
        // (a+)+ / (a*)* / (.+)+ / (\w+\s?)*：量词套量词
        Regex::new(r"\([!-~]{1,60}[+*?]\)[+*]").unwrap(),
        // (a+){2,}：量词套有界重复
        Regex::new(r"\([!-~]{1,60}[+*?]\)\{\d+,\}").unwrap(),
        // (a{2,})* / (a{2,}){3,}：{n,} 套外层量词
        Regex::new(r"\([!-~]{1,60}\{\d+,\}\)[+*]").unwrap(),
        Regex::new(r"\([!-~]{1,60}\{\d+,\}\)\{\d+,\}").unwrap(),
        // (.|x)+ / (a|b|.)*：`.` 与任何分支重叠，必然回溯。只认 `|.` / `.|`
        // ——`.` 得是分支本身。写成"括号里有 `.`"会连 `(图 1.2)*` 这种脚注标记一起报。
        Regex::new(&[r"\([!-~]{0,60}(?:\|\.|\.\|)[!-~]{0,60}\)", Q].concat()).unwrap(),
        // (\d|\w)* / (\w|y)*：字符类分支与落在类里的分支重叠。
        // ([0-9]|[a-z]) 这类互斥字符类不算，`(a|b)*` 这类互斥单字符更不算。
        Regex::new(&[r"\(\\[dwsDWS]\|(?:\\[dwsDWS]|[A-Za-z0-9_])\)", Q].concat()).unwrap(),
        // (x|)* / (|x)*：空分支能匹配任何东西，与其余分支全重叠
        Regex::new(&[r"\((?:[!-~]{0,60}\||\|[!-~]{0,60})\)", Q].concat()).unwrap(),
    ]
});

/// `regex` crate 没有反向引用，`(a|a)*`（分支相同）和 `(a|ab)*`（分支同前缀）只有逐字符
/// 比较才能判定——正则表达不了。只解析最外层括号、只看"首分支是单字符"的情形：它正是
/// 被"首分支 ≤1 字符即重叠"启发式误伤的那一类。返回命中的 `(` 位置与外层量词前面的长度。
fn repeated_prefix_branch(input: &str) -> Option<(usize, usize)> {
    for (open, _) in input.match_indices('(') {
        let Some(rel_close) = input[open..].find(')') else {
            continue;
        };
        let close = open + rel_close;
        // 只认紧跟 * / + / {n,}（带逗号才算无上界，`{2}` 是有界重复，不爆炸）
        let tail = &input[close + 1..];
        let quant_len = match tail.chars().next() {
            Some('*' | '+') => 1,
            Some('{') => match tail.find('}') {
                Some(e) if tail[..e].contains(',') => e + 1,
                _ => 0,
            },
            _ => continue,
        };
        if quant_len == 0 {
            continue;
        }
        let mut branches = input[open + 1..close].split('|');
        // 首分支必须是单个 ASCII 字母数字：`[0-9]` 这类字符类分支不在本函数范围内
        let Some(first) = branches.next() else {
            continue;
        };
        let mut fc = first.chars();
        let (Some(c), None) = (fc.next(), fc.next()) else {
            continue;
        };
        if c.is_ascii_alphanumeric() && branches.any(|b| b.starts_with(c)) {
            return Some((open, quant_len));
        }
    }
    None
}

pub struct ReDoSDetector;

impl Detector for ReDoSDetector {
    fn name(&self) -> &'static str {
        "redos"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        if let Some((open, quant_len)) = repeated_prefix_branch(input) {
            let end = input[open..].find(')').map_or(input.len(), |e| open + e + 1 + quant_len);
            return Some(DetectionResult {
                attack_type: self.name().to_string(),
                category: AttackCategory::Data,
                severity: Severity::Medium,
                matched_pattern: input[open..end].to_string(),
                offset: open,
                message: "Catastrophic backtracking pattern detected".into(),
            });
        }
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
    fn ignores_disjoint_alternation() {
        // 分支互斥 = 没有回溯歧义，(a|b)* 是线性匹配。旧启发式只看"首分支 ≤1 字符"，
        // 把这类正常正则和中文正文里的括号星号全算成了 ReDoS。
        for input in [
            "(a|b)*",
            "(0|1)+",
            "(y|n)*",
            "(x|y|z)+",
            "^(a|b)+$",
            "(a|b){2,}",
            "(?i)(a|b)*",
            "选项(是|否)*",
            "步骤(1|2)*3",
            "价格 (元+)* 说明",
            "注意(重要+)*提醒",
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
    fn still_reports_same_prefix_branches() {
        // 分支相同 / 同前缀才是真重叠——`regex` crate 没有反向引用，这条走字符串比较
        for input in ["(a|a)*", "(a|ab)*", "(a|a){1,}"] {
            assert_hit(input);
        }
        // 有界重复 `{2}` 不爆炸
        assert_clean(&det(), "(a|a){2}");
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
