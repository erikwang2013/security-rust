// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 只报三类高信号形态：%n 写内存、连续泄露符读栈、超宽宽度炸 CPU。
// 单个 %s/%d 是正常占位符，不报。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // %n / %hn / %lln / %1$n：唯一能写内存的转换符
        Regex::new(r"%(?:\d{1,9}\$)?(?:hh|h|ll|l|L|z|j|t|q)?n\b").unwrap(),
        // 宽度炸弹：%99999999d
        Regex::new(r"%\d{6,}[diouxXeEfgGaAcspn]").unwrap(),
        // %x%x%x%x / %p%p%p%p：连续读栈，允许 %08x.%08x 这种短分隔
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?[xXp][.\-_,: ]{0,2}){3,}").unwrap(),
        // 四个以上连续 %s：挨个读栈上字符串
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?s[.\-_,: ]{0,2}){4,}").unwrap(),
        // 混合连续泄露：%s%x%p%n 这类穿插写法
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?[sxXp][.\-_,: ]{0,2}){6,}").unwrap(),
    ]
});

pub struct FormatStringDetector;

impl Detector for FormatStringDetector {
    fn name(&self) -> &'static str {
        "format_string"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Injection, Severity::Medium, "Format string injection detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> FormatStringDetector {
        FormatStringDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Injection, Severity::Medium);
    }

    #[test]
    fn name_is_format_string() {
        assert_eq!(det().name(), "format_string");
    }

    #[test]
    fn detects_percent_n_variants() {
        for input in [
            "%n",
            "AAAA%n",
            "%1$n",
            "%hn",
            "%lln",
            "%08x%08x%08x%n",
            "%p %p %n",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_width_bomb() {
        for input in [
            "%99999999d",
            "%1000000s",
            "AAAA%2147483647d",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_repeated_leak_specifiers() {
        for input in [
            "%x%x%x%x",
            "%p%p%p",
            "%08x.%08x.%08x.%08x",
            "%s%s%s%s",
            "%x%p%s%x%p%s",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "100% safe",
            "50% off",
            "discount 20%",
            "%s 是占位符",
            "%d%%",
            "printf(\"%s\\n\", name)",
            "a % b",
            "下载进度 88%",
            "http://example.com/?q=%20name",
            "100%name",
            "url: a%2Fb%3Fc",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "%");
        assert_clean(&det(), "%%");
        assert_clean(&det(), "%s");
        assert_clean(&det(), "%s%s%s");
        // 连续泄漏不足 3 次
        assert_clean(&det(), "%x%x");
        assert_clean(&det(), "%p%p");
    }
}
