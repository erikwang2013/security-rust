// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

// 强档：伪协议 URI。形态约束是「scheme 后面**跟着内容**」——
// `javascript:` 后面必须是实参（`javascript:alert(1)`），`data:text/html` 后面必须
// 是 `,` 或 `;` 分段（没有数据段的 data URI 根本不是合法 URI）。散文里的
// `The javascript: URL scheme is blocked by the CSP.` / `the data:text/html payload`
// 只是术语，不报。
// 三条同档模式合成一条 alternation：一次 `find_iter` 扫完三条分支，而不是逐条
// `find_iter` 各扫一遍。`(?i)` 为三条分支所共有，提到最前——它的作用域是整条模式
// （含 `|` 之后的全部分支），与逐条编译时每条各自带 `(?i)` 等价。
// 下面 `detect()` 里 `://` 前缀的跳过逻辑不变：它按「匹配起点前一个字节是不是 `:`」判，
// 与模式怎么分组无关。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            r"(?i)javascript\s*:[^\s]",
            r"|data\s*:\s*text/html\s*[,;]",
            r"|data\s*:\s*text/plain\s*[,;]",
        ]
        .concat(),
    )
    .unwrap()
});

// 弱档：`//host.tld`（协议相对 URL）。攻击形态 `?next=//evil.com` 与正常内容里
// 出现的协议相对 URL 逐字节同形——源码注释 `//github.com/owner/repo`、文档
// `Use //cdn.example.com/x.js`——正则分不开，所以只报 Low：仍然命中，但不单独
// 越线，也不参与"多条 Medium 叠加成 High"。
// `://` 前缀的跳过见 detect()：`http://www.w3.org` 里的 `//` 是 scheme 的一部分。
//
// 本模式的天花板就在这里，不要试图再收紧：token 起始处的协议相对 URL（上面那两个
// 例子）**仍会命中 Low**——它们与攻击逐字节相同，只有值（跳去哪个主机）能区分，
// 而值在正常内容里同样合法。能收紧的只有"嵌在更长 URL 里"的那一半，已由上面的
// `://` 跳过覆盖。
static WEAK_PATTERNS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)//[^/\s]+\.[a-z]{2,}").unwrap());

pub struct OpenRedirectDetector;

impl Detector for OpenRedirectDetector {
    fn name(&self) -> &'static str {
        "open_redirect"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        for (re, severity) in [
            (&*STRONG_PATTERNS, Severity::Medium),
            (&*WEAK_PATTERNS, Severity::Low),
        ] {
            for m in re.find_iter(input) {
                let start = m.start();
                // `//` 紧跟在 `:` 后面时属于更长的 URL，不是重定向目标：
                // `http://www.w3.org/2000/svg` 的 `//` 是 scheme 的一部分。
                if start > 0 && input.as_bytes()[start - 1] == b':' {
                    continue;
                }
                return Some(DetectionResult {
                    attack_type: "open_redirect".into(),
                    category: AttackCategory::Protocol,
                    severity,
                    matched_pattern: m.as_str().to_string(),
                    offset: start,
                    message: "Open redirect detected".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        assert_hit_at(input, Severity::Medium);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(
            &OpenRedirectDetector,
            input,
            AttackCategory::Protocol,
            severity,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&OpenRedirectDetector, input);
    }

    #[test]
    fn name_is_open_redirect() {
        assert_eq!(OpenRedirectDetector.name(), "open_redirect");
    }

    /// 弱档：协议相对 URL 仍然命中，只是不再单独越线（见下面的注释/文档样例）。
    #[test]
    fn detects_double_slash_url() {
        assert_hit_at("//evil.com/phishing", Severity::Low);
        assert_hit_at("//attacker.org/steal?u=1", Severity::Low);
        assert_hit_at("https://ok.com//evil.com", Severity::Low); // scheme match skipped, later redirect still caught
    }

    #[test]
    fn detects_javascript_uri() {
        assert_detected("javascript:alert(document.cookie)");
    }

    #[test]
    fn detects_data_html_uri() {
        assert_detected("data:text/html,<script>alert(1)</script>");
    }

    #[test]
    fn detects_data_plain_uri() {
        assert_detected("data: text/plain;base64,SGVsbG8=");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("JAVASCRIPT:alert(1)");
        assert_hit_at("//Evil.Com/", Severity::Low);
    }

    /// 术语 vs 用法：散文里裸的 scheme 名（后面跟空格/标点）不是 URI 用法；
    /// `data:` 光有 MIME 而没有数据分段也不构成合法 URI。旧模式
    /// （`javascript\s*:` / `data\s*:\s*text/html`）把这三条都判 Medium。
    #[test]
    fn prose_mentioning_schemes_is_clean() {
        assert_clean("The javascript: URL scheme is blocked by the CSP in modern browsers.");
        assert_clean("Browsers render the data:text/html payload as a document.");
        assert_clean("Prefer data:text/plain for the log preview.");
    }

    /// 协议相对 URL 在正常内容里的样子：源码注释、文档里的 CDN 链接。
    /// 它们与攻击同形，所以是弱档命中（5 分）而不是干净。
    #[test]
    fn protocol_relative_urls_in_docs_hit_only_the_weak_tier() {
        for input in [
            "//github.com/rust-lang/rust/issues/1\nfn main() {}\n",
            "Use //cdn.example.com/x.js only when the CDN has TLS available.\n",
        ] {
            assert_hit_at(input, Severity::Low);
        }
        // 文档里的绝对 URL 不走弱档：`//` 前面是 `:`，属于 scheme
        assert_clean("See https://example.com/docs?a=1&a=2 for details.");
        assert_clean(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"/>"#);
    }

    #[test]
    fn rejects_scheme_urls() {
        assert_clean("https://evil.com/phishing");
        assert_clean("http://example.com/");
        assert_clean("file:///etc/passwd");
    }

    #[test]
    fn rejects_benign_paths() {
        assert_clean("example.com/redirect");
        assert_clean("java script: alert(1)");
        assert_clean("data:image/png;base64,AA==");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("//evil/com");
        assert_clean("//evil.c");
        assert_clean("// evil.com");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("重定向到登录页");
    }
}
