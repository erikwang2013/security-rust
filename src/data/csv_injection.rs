// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // 行首公式起始符。制表符与回车**不是**公式起始——它们是分隔符：
        // `"\t\n\r"`（制表符分隔的空行）和 `"a\r\n\r\nb"`（CRLF 空行）
        // 都曾被这一条判成数据注入。
        Regex::new(r"(?m)^[=+\-@]").unwrap(),
        // 字段分隔符之后的 `=`：`admin,=1+1`、`x;=HYPERLINK(...)`、`\t=1`、
        // `,"=cmd|..."`。两条收紧：
        //   - 只认 `=`——`,`/`;`/`\t` 后的 `+`/`-`/`@` 在散文里太常见
        //     （`1, -2, -3`、`me, @alice`）；
        //   - `=` 后面必须紧跟非空白——`key\t= value` 这种制表符对齐的配置
        //     不是公式，公式里 `=` 后面是操作数。
        Regex::new(r#"(?m)[,;\t][ \t]*"?[ \t]*=[^ \t]"#).unwrap(),
        Regex::new(r"(?im)^\s*DDE").unwrap(),
        Regex::new(r"(?im)^\s*cmd\s*\|").unwrap(),
        Regex::new(r"(?im)^\s*@SUM\s*\(").unwrap(),
    ]
});

pub struct CsvInjectionDetector;

impl Detector for CsvInjectionDetector {
    fn name(&self) -> &'static str {
        "csv_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            &PATTERNS,
            self.name(),
            AttackCategory::Data,
            Severity::Medium,
            "CSV formula injection detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(CsvInjectionDetector.name(), "csv_injection");
    }

    #[test]
    fn detects_formula_prefixes() {
        for payload in [
            "=cmd|' /C calc'!A0",
            "+1+1",
            "-2+3",
            "@SUM(1+1)*cmd",
            "\t=1",
            "列1\t=1",
            "admin,=1+1",
            "x;=HYPERLINK(\"http://evil.com\")",
            ",\"=cmd|' /C calc'!A0\"",
            "DDE;cmd",
            "cmd|' /C calc'!A0",
        ] {
            let r = CsvInjectionDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "csv_injection");
            assert_eq!(r.category, AttackCategory::Data);
            assert_eq!(r.severity, Severity::Medium);
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "a=1+1",
            "SUM(1+1)",
            "cmd /C calc",
            "not a formula",
            // 空白字符是分隔符，不是公式起始符
            "\t\n\r",
            "a\tb",
            "列1\t列2\t列3",
            "hello world",
            "line one\r\n\r\nline two",
            "a, b, c",
            "2024-01-01",
            // 逗号后的 `+`/`-`/`@` 是散文形态，不认
            "1, -2, -3",
            "me, @alice",
        ] {
            assert!(
                CsvInjectionDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(CsvInjectionDetector.detect("").is_none());
        assert!(CsvInjectionDetector.detect("   ").is_none());
        assert!(CsvInjectionDetector.detect("＝cmd|' /C calc'!A0").is_none()); // fullwidth equals
    }
}
