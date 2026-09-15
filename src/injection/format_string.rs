// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

// 只报三类高信号形态：%n 写内存、连续泄露符读栈、超宽宽度炸 CPU。
// 单个 %s/%d 是正常占位符，不报。
// 分隔符只留 `.`/`-`/`_`/`:`：`,` 和空格是 printf 模板的常规分隔
// （`printf("%s, %s, %s, %s\n", ...)`、`INSERT INTO t VALUES (%s, %s, %s, %s)`），
// 放进来等于把正常 SQL/printf 模板全打成注入。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // %n / %hn / %lln / %1$n：唯一能写内存的转换符。
        // 前边界排除数字：`100%n`、`50%n/a` 是百分比串（还是它们真的想 printf `100%n`？）
        // ——按"误报比漏报更糟"取舍，紧跟在数字后面的 %n 放过。
        Regex::new(r"(?:^|[^0-9])%(?:\d{1,9}\$)?(?:hh|h|ll|l|L|z|j|t|q)?n\b").unwrap(),
        // 宽度炸弹：%99999999d
        Regex::new(r"%\d{6,}[diouxXeEfgGaAcspn]").unwrap(),
        // %x%x%x / %p%p%p：连续读栈（中间没有分隔符，3 个就够）
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?[xXp]){3,}").unwrap(),
        // %08x.%08x.%08x.%08x：带分隔的读栈。`.` 在正常格式串里常见（日期、UUID），
        // 所以阈值提到 4——`%08x.%08x.%08x` 那个量级是格式串，不是栈转储。
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?[xXp][.\-_:]?){4,}").unwrap(),
        // 四个以上连续 %s：挨个读栈上字符串
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?s[.\-_:]{0,2}){4,}").unwrap(),
        // 混合连续泄露：%s%x%p%n 这类穿插写法
        Regex::new(r"(?:%[0-9]{0,4}(?:hh|h|ll|l|L|z|j|t|q)?[sxXp][.\-_:]{0,2}){6,}").unwrap(),
    ]
});

pub struct FormatStringDetector;

impl Detector for FormatStringDetector {
    fn name(&self) -> &'static str {
        "format_string"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            &PATTERNS,
            self.name(),
            AttackCategory::Injection,
            Severity::Medium,
            "Format string injection detected",
            input,
        )
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
        for input in ["%99999999d", "%1000000s", "AAAA%2147483647d"] {
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
    fn ignores_normal_printf_and_sql_templates() {
        // 分隔符含 `,`/空格时，正常的多占位符模板会被当成"连续读栈"：
        // printf 的 `%s, %s, %s, %s`、SQL 的 `VALUES (%s, %s, %s, %s)` 都是日常写法。
        for input in [
            "printf(\"%s, %s, %s, %s\\n\", a, b, c, d)",
            "INSERT INTO t VALUES (%s, %s, %s, %s)",
            "score=%s; name=%s; tag=%s; note=%s",
            "user=%s ip=%s",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn ignores_short_leak_sequences() {
        // 3 个 %x 是调试格式串（`%08x.%08x.%08x` 打 MAC/时间戳），不是栈转储；
        // 带分隔的阈值提到 4。
        for input in ["%x %x %x", "%08x.%08x.%08x"] {
            assert_clean(&det(), input);
        }
        // 连续无分隔的 3 个仍报
        assert_hit("%x%x%x");
    }

    #[test]
    fn ignores_percent_sign_after_digits() {
        // `100%n` / `50%n/a` 里的 `%n` 紧跟在数字后——百分比串。加了前边界后放过。
        for input in ["100%n", "50%n/a"] {
            assert_clean(&det(), input);
        }
        assert_hit("AAAA%n");
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
