// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：公式必须落在**单元格**里（行首或字段分隔符之后）且形态本身指向
/// 「能执行 / 能外带」——`=cmd|`、`@SUM(`、`DDE`。
/// 各分支合成一条 alternation（原来 N 条要各扫一遍）。flags **不一致**，
/// 故每条都收在自己的 `(?…:…)` 组里——裸 `(?im)` 会顺延到后面的分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            // 字段分隔符之后的 `=`：`admin,=1+1`、`x;=HYPERLINK(...)`、`\t=1`、
            // `,"=cmd|..."`。两条收紧：
            //   - 只认 `=`——`,`/`;`/`\t` 后的 `+`/`-`/`@` 在散文里太常见
            //     （`1, -2, -3`、`me, @alice`）；
            //   - `=` 后面必须紧跟非空白——`key\t= value` 这种制表符对齐的配置
            //     不是公式，公式里 `=` 后面是操作数。
            r#"(?m:[,;\t][ \t]*"?[ \t]*=[^ \t])"#,
            r"|(?im:^\s*DDE)",
            r"|(?im:^\s*cmd\s*\|)",
            r"|(?im:^\s*@SUM\s*\()",
        ]
        .concat(),
    )
    .unwrap()
});

/// 弱信号：行首前缀**后面必须跟内容**。裸前缀在正常文本里遍地都是——MIME 分隔行
/// `--boundary123--`（每个 multipart 请求体都有若干条）、markdown 列表项 `- item`、
/// 分隔线 / YAML front matter 的 `---`、setext 标题下划线 `=====`、代码里的 `++i`
/// 全是这个形态。于是前缀后既不能是另一个 `=`/`+`/`-`（挡掉 `--`、`===`、`++i`），
/// 也不能是空白（挡掉 `- item`）——实测本仓库 361 个文本文件命中数从 214 降到 0。
///
/// `@` 整个移出粗粒度层：公式里的 `@` 只会以 `@SUM(` 这类函数形态出现，本文件下一条
/// `^\s*@SUM\(` 与 formula_injection 的函数名录已完整覆盖，而 `@media` / `@import`
/// 这类 CSS at-rule 在样式表里遍地都是。收紧后仍报 Low 而不是 Medium：
/// `-2 degrees` 这种散文里的负数（前缀 + 数字，与 `-2+3` 字节同形）无法用正则与
/// 单元格里的公式区分，单条不足以触发拒绝。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    // 制表符与回车**不是**公式起始——它们是分隔符：`"\t\n\r"`（制表符分隔的空行）
    // 和 `"a\r\n\r\nb"`（CRLF 空行）都曾被这一条判成数据注入。
    Regex::new(r"(?m)^[=+\-][^=+\-\s]").unwrap()
});

pub struct CsvInjectionDetector;

impl Detector for CsvInjectionDetector {
    fn name(&self) -> &'static str {
        "csv_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Data,
            Severity::Medium,
            "CSV formula injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Data,
                Severity::Low,
                "CSV formula prefix present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> CsvInjectionDetector {
        CsvInjectionDetector
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        assert_detected(&det(), input, AttackCategory::Data, severity);
    }

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(CsvInjectionDetector.name(), "csv_injection");
    }

    #[test]
    fn detects_formula_prefixes() {
        // 强信号：落在单元格边界（行首或分隔符之后）且形态指向执行/外带，Medium
        for payload in [
            "@SUM(1+1)*cmd",
            "\t=1",
            "列1\t=1",
            "admin,=1+1",
            "x;=HYPERLINK(\"http://evil.com\")",
            ",\"=cmd|' /C calc'!A0\"",
            "DDE;cmd",
            "cmd|' /C calc'!A0",
        ] {
            assert_hit_at(payload, Severity::Medium);
        }
        // 弱信号：只有行首前缀本身，Low——仍检出，但单条不越过拒绝线
        for payload in ["=cmd|' /C calc'!A0", "+1+1", "-2+3"] {
            assert_hit_at(payload, Severity::Low);
        }
    }

    /// 弱信号里剩下的形态：前缀 + 内容（`-2`、`=1`）。它仍检出，但只有 Low——
    /// 散文里的负数与单元格里的公式字节同形，单条不足以拒绝。
    #[test]
    fn prefix_followed_by_content_is_low() {
        for input in [
            "-2+3",
            "-2 degrees overnight",
            "=1+1",
            "+1 more item",
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    /// 裸前缀**不是**公式。MIME 分隔行是每一个 multipart 请求体都带的字节，
    /// markdown 列表项 / 分隔线 / setext 下划线 / `++i` 同理。这些必须
    /// **干净**（不是 Low）——收紧后的形态要求前缀后面跟内容，它们连前缀都不算。
    /// 实测本仓库 361 个文本文件：收紧前 214 个命中，收紧后 0 个。
    #[test]
    fn bare_prefixes_are_clean() {
        for input in [
            "--x--",
            "--boundary123--",
            "----------------------------d74496d66958873e",
            "- item",
            "--",
            "---",
            "=====",
            "++i;",
            "@media (max-width: 640px) { .card { flex-direction: column; } }",
            "## Deployment\n\n- item one\n- item two",
            "Title\n=====",
        ] {
            assert_clean(&det(), input);
        }
    }

    /// 真实 multipart 请求体：分隔行是 `--` + boundary，每段之间都有一条。
    /// mail_header 的 `Content-Type: multipart` / `boundary=` 已删除后，
    /// 这一条曾是本库最后一个会在正常上传上报的检测器。
    #[test]
    fn real_multipart_upload_is_clean() {
        let body = "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.5.0\r\n\
Content-Type: multipart/form-data; boundary=------------------------d74496d66958873e\r\n\
Content-Length: 4096\r\n\
\r\n\
----------------------------d74496d66958873e\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n\
Content-Type: application/pdf\r\n\
\r\n\
%PDF-1.4 binary payload\r\n\
----------------------------d74496d66958873e\r\n\
Content-Disposition: form-data; name=\"note\"\r\n\
\r\n\
- reproduced on staging\r\n\
----------------------------d74496d66958873e--\r\n";
        assert_clean(&det(), body);
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
