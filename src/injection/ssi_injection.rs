// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：只能是恶意用法 —— 执行命令、导出整个环境、包含绝对路径 / `..` 穿越。
/// 3 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 3 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"<!--#exec cmd=",
        // `<!--#include file="header.html" -->` 是 Apache SSI 的常规写法（每一个
        // .shtml 页面都有），只有绝对路径或 `..` 穿越才是注入。
        r#"|<!--#include file=["']?(?:/|\.\.)"#,
        r"|<!--#printenv",
    ))
    .unwrap()
});

/// 弱信号：SSI 指令「出现」本身就是这些指令的功能 —— echo 变量、fsize/flastmod
/// 取文件信息、config 设格式、相对路径 include，正常与恶意形状完全相同，单条不拒绝。
/// 5 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 5 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"<!--#include file=",
        r"|<!--#echo var=",
        r"|<!--#fsize",
        r"|<!--#flastmod",
        r"|<!--#config",
    ))
    .unwrap()
});

pub struct SsiInjectionDetector;

impl Detector for SsiInjectionDetector {
    fn name(&self) -> &'static str {
        "ssi_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::High,
            "SSI Server-Side Include injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "SSI directive present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SsiInjectionDetector {
        SsiInjectionDetector
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(&det(), input, AttackCategory::Injection, severity);
    }

    #[test]
    fn name_is_ssi_injection() {
        assert_eq!(det().name(), "ssi_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for (input, severity) in [
            // 强信号：可执行 / 越权读取，High
            (r#"<!--#exec cmd="cat /etc/passwd"-->"#, Severity::High),
            (r#"<!--#include file="/etc/passwd"-->"#, Severity::High),
            (r#"<!--#include file="../../etc/passwd"-->"#, Severity::High),
            (r#"<!--#printenv-->"#, Severity::High),
            // 弱信号：指令出现本身即正常 SSI 功能，Low
            (r#"<!--#echo var="DATE_LOCAL"-->"#, Severity::Low),
            (r#"<!--#fsize file="index.html"-->"#, Severity::Low),
            (r#"<!--#flastmod file="index.html"-->"#, Severity::Low),
            (r#"<!--#config timefmt="%B"-->"#, Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }

    /// 正常 .shtml 页面。`include file="footer.html"` / `echo var="DATE_LOCAL"` /
    /// `config timefmt=…` 是 Apache SSI 的文档写法，每个用了服务端包含的站点都有；
    /// 它们曾按 High 被判注入，整页被拒。
    #[test]
    fn stock_ssi_page_is_not_high() {
        let page = "<!--#include file=\"header.html\" -->\n\
                    <!--#echo var=\"DATE_LOCAL\" -->\n\
                    <!--#config timefmt=\"%Y\" -->\n\
                    <!--#fsize file=\"footer.html\" -->";
        assert_hit_at(page, Severity::Low);
        // 弱信号仍检出（不是「删掉检测」），只是不再单独越过拒绝线
        assert!(det().detect(page).is_some());
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "<!-- this is a plain comment -->",
            "The page was generated at 3:00 PM",
            "Include the file below the table",
            "The include directive resolves the path at build time.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: directive incomplete, or uppercase (patterns are case-sensitive)
        assert!(det().detect("<!--#exec").is_none());
        assert!(det().detect(r#"<!--#EXEC cmd="ls"-->"#).is_none());
        assert!(det().detect("<!-- #exec cmd=\"ls\" -->").is_none());
    }
}
