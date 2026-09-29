// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：单独出现即可判 Critical —— 攻击者可控的「可执行」形态。
/// 正常内容里几乎不会出现，出现即是 XSS。
/// 3 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 3 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 各分支共同的 `(?i)` 提升为外层 `(?i:…)`，作用域正好覆盖全部 3 条分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // 事件处理器白名单：每个分支都必须以字面量 `on` 开头，否则 `phone=`、`zone=`、
        // `one=` 这类普通属性会误报。分支覆盖 handler 族（`mouse\w*` 等），
        // 而不是逐个枚举成员 —— 枚举漏掉的 `onmouseenter` / `onpointerover` /
        // `onpaste` / `ondragstart` / `oncontextmenu` / `onanimationiteration` /
        // `onbeforeunload` 曾整体漏检。
        r"(?i:on(?:error|load\w*|click|mouse\w*|key\w*|focus|blur|before\w*|change|submit|reset|scroll|resize|abort|select|start|drag\w*|drop|play|pause|ended|volumechange|animation\w*|transition\w*|touch\w*|pointer\w*|wheel|auxclick|can\w*|close|cue\w*|dblclick|duration\w*|emptied|fullscreenchange|got\w*|input|invalid|lost\w*|offline|online|page\w*|pop\w*|progress|ratechange|securitypolicyviolation|seek\w*|show|stalled|suspend|timeupdate|toggle|waiting|paste|copy|cut|contextmenu)\s*=",
        // 只认「scheme 后紧跟非空白」的形式，裸的 `javascript:` 短语（散文、文档）不报。
        r"|javascript:[^\s]",
        // 与 `javascript:` 同样只认「scheme 后紧跟非空白」：散文里的 bare `vbscript:`
        // 不报（老 IE 时代的技术文档里满地都是），`vbscript:msgbox(1)` 照报。
        r"|vbscript:[^\s])",
    ))
    .unwrap()
});

/// 弱信号：标签 / 函数名「出现」本身在正常页面里极常见 —— `<script src="/app.js">`
/// 几乎每个网页都有 —— 但它确实是 XSS 的载体。所以报 Low 而不是 Critical：
/// 单条 5 分不至于触发拒绝，由调用方按聚合分（多条叠加）决定，误报旋钮留给上层。
/// 6 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 6 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 各分支共同的 `(?i)` 提升为外层 `(?i:…)`，作用域正好覆盖全部 6 条分支。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i:<script[\s/>]",
        r"|<iframe[\s/>]",
        r"|<embed[\s/>]",
        r"|<object[\s/>]",
        r"|<link[\s/>]",
        r"|expression\s*\()",
    ))
    .unwrap()
});

pub struct XssDetector;

impl Detector for XssDetector {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "XSS cross-site scripting detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "XSS tag present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> XssDetector {
        XssDetector
    }

    fn assert_hit(input: &str) {
        assert_hit_at(input, Severity::Critical);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(&det(), input, AttackCategory::Injection, severity);
    }

    #[test]
    fn name_is_xss() {
        assert_eq!(det().name(), "xss");
    }

    #[test]
    fn detects_common_payloads() {
        for (input, severity) in [
            // 强信号：可执行形态，Critical
            ("<img src=x onerror=alert(1)>", Severity::Critical),
            ("javascript:alert(document.cookie)", Severity::Critical),
            ("vbscript:msgbox(1)", Severity::Critical),
            ("<svg onload=alert(1)>", Severity::Critical),
            // 弱信号：标签出现本身，Low（聚合升级由调用方决定）
            ("<script>alert(1)</script>", Severity::Low),
            ("<iframe src=\"//evil.com\"></iframe>", Severity::Low),
            ("data:text/html,<script>alert(1)</script>", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }

    /// 标签族分档：`<script src>` 这类在真实网页里遍地都是，必须是 Low 而不是
    /// Critical，否则「带外链脚本的正常页面」仍会被整页拒绝。
    #[test]
    fn tag_presence_is_low_not_critical() {
        for input in [
            r#"<link rel="stylesheet" href="/s.css">"#,
            r#"<script src="/app.js" defer></script>"#,
            r#"<iframe src="https://maps.example.com/embed"></iframe>"#,
            r#"<embed src="/whitepaper.pdf" type="application/pdf">"#,
            r#"<object data="logo.svg" type="image/svg+xml"></object>"#,
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    /// 事件处理器族。旧枚举只列到 `pointerdown|pointerup`、`mouse(over|out|down|up|move)`、
    /// `animationstart|animationend`，下面这些曾整体漏检；`onerror` / `onload` / `onclick`
    /// 是最常见的三个 handle，必须仍然命中。
    #[test]
    fn detects_event_handler_families() {
        for input in [
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<div onclick=alert(1)>x</div>",
            "<div onmouseenter=alert(1)>",
            "<img src=x onpointerover=alert(1)>",
            "<input onpaste=alert(1)>",
            "<b ondragstart=alert(1)>",
            "<div oncontextmenu=alert(1)>",
            "<div onanimationiteration=x>",
            "<div onbeforeunload=x>",
        ] {
            assert_hit(input);
        }
    }

    /// 真实语料。弱上下文模式（`window.location` / `document.cookie` / `eval(` /
    /// `data:text/html` / `<svg` / `<meta`）曾把下面每一条都判成 Critical，
    /// 而它们全是普通页面内容 —— 这是「整个正常网页被拒」的根因。
    #[test]
    fn real_world_inputs_not_detected() {
        for input in [
            // 普通 HTML 页面片段
            r#"<!DOCTYPE html>
<html lang="en"><head><title>Docs</title></head>
<body><h1>Welcome</h1><p>Read the <a href="/about">about page</a>.</p>
<img src="/logo.png" alt="logo" width="120">
</body></html>"#,
            // 普通 SVG 文件（`docs/pet.svg` 曾被自家扫描器判 Critical）
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <path d="M12 2 2 22h20z" fill="none" stroke="#333" stroke-width="2"/>
  <circle cx="12" cy="12" r="4" fill="#09f"/>
</svg>"##,
            // 普通 JS 文本
            r#"const url = window.location.href;
document.cookie = "session=abc; path=/";
const total = price * qty && discount > 0;
const out = eval(userCode);"#,
            // 普通 CSS 块
            "body { margin: 0; font-family: system-ui, sans-serif; }\n.card { display: flex; gap: 8px; color: #334155; }",
            // Markdown 表格与 JS 逻辑与表达式
            "| Name | Age | City |\n|------|-----|------|\n| Ada | 36 | London |",
            "if (a && b) { run(); }",
            // 散文里的 DOM 名词
            "The window.location object gives you the current URL.",
            "Cookies are read via document.cookie and written with document.write().",
            // 散文里的 bare `vbscript:`（紧跟空格）不是 scheme 用法
            "The legacy page used vbscript: syntax in an old IE-only build.",
            // 含 `on` 前缀的普通属性值：朴素 `on\w*=` 会在这三处误报
            "phone=555-1234",
            "zone=UTC&timezone=Europe/Berlin",
            "<div one=1>",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The weather today is sunny with a high of 25 degrees.",
            "Please call the office at 555-1234 for assistance.",
            "Welcome to our website, please enjoy your stay.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect("   \t\n  ").is_none());
        assert!(det().detect("こんにちは世界 你好").is_none());
        // near misses: keyword present but not the payload form
        assert!(det().detect("script alert(1)").is_none());
        assert!(det().detect("javascript alert(1)").is_none());
        assert!(det().detect("vbscript msgbox(1)").is_none());
        assert!(det().detect("evaluate this expression carefully").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for (input, severity) in [
            ("<img src=x OnErRoR=alert(1)>", Severity::Critical),
            ("JaVaScRiPt:alert(1)", Severity::Critical),
            ("<SVG/onload=alert(1)>", Severity::Critical),
            ("<SCRIPT>alert(1)</SCRIPT>", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }
}
