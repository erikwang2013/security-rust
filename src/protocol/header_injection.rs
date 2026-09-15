// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(
            r"(?i)\r\n\s*(?:Set-Cookie|Location|Content-Length|Content-Type|Transfer-Encoding|Refresh|Status|WWW-Authenticate):",
        )
        .unwrap(),
        Regex::new(r"(?i)%0[dD].*%0[aA]").unwrap(),
        // 反序对 LF-CR。部分解析器容忍这个顺序，是响应拆分的绕过变体。
        // 编码形态在正常文本里不出现，误报面与上面那条同量级。
        // （原先由 crlf_injection 覆盖，该检测器因 LF-only 分支误报、其余形态
        // 与本检测器重复而删除，其独有的这几条形态改由这里接手。）
        Regex::new(r"(?i)%0[aA].*%0[dD]").unwrap(),
    ]
});

pub struct HeaderInjectionDetector;

impl Detector for HeaderInjectionDetector {
    fn name(&self) -> &'static str {
        "header_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::High, "HTTP header injection (CRLF) detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &HeaderInjectionDetector,
            input,
            AttackCategory::Protocol,
            Severity::High,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&HeaderInjectionDetector, input);
    }

    #[test]
    fn name_is_header_injection() {
        assert_eq!(HeaderInjectionDetector.name(), "header_injection");
    }

    #[test]
    fn detects_encoded_crlf_set_cookie() {
        assert_detected("test%0d%0aSet-Cookie: evil=true");
    }

    #[test]
    fn detects_encoded_crlf_location() {
        assert_detected("redirect?url=%0D%0ALocation: /admin");
    }

    #[test]
    fn detects_encoded_crlf_content_length() {
        assert_detected("body%0d%0aContent-Length: 0");
    }

    #[test]
    fn detects_raw_crlf_headers() {
        assert_detected("foo\r\nContent-Type: text/html");
        assert_detected("bar\r\nTransfer-Encoding: chunked");
    }

    #[test]
    fn detects_scattered_encoded_crlf() {
        assert_detected("a%0dcontent%0a");
    }

    #[test]
    fn detects_reverse_order_encoded_crlf() {
        // 反序对 LF-CR：部分解析器容忍，是响应拆分的绕过变体。
        // 这组形态原先由已删除的 crlf_injection 覆盖，现在归本检测器。
        assert_detected("%0a%0d");
        assert_detected("value%0a%0dSet-Cookie: session=evil");
        assert_detected("a%0Acontent%0D");
    }

    #[test]
    fn detects_injection_via_redirect_headers() {
        // Refresh / Status / WWW-Authenticate 同样可用于响应拆分，
        // 原先只在 crlf_injection 的裸 \r\n 名录里，现已并入本检测器
        assert_detected("value\r\nRefresh: 0;url=http://evil.com");
        assert_detected("value\r\nStatus: 302");
        assert_detected("value\r\nWWW-Authenticate: Basic realm=x");
    }

    #[test]
    fn rejects_lf_only_prose() {
        // 这几条正是旧 crlf_injection 被删除的原因：只认 \r\n，不认裸 \n，
        // 否则任何多行文本 / YAML / 日志粘贴都会被判 High。此测试防止回归。
        assert_clean("Meeting at 3pm\nlocation: Room 5");
        assert_clean("笔记\nset-cookie: abc");
        assert_clean("配置:\nrefresh: 30\nlocation: /var/www");
        assert_clean("note\ncontent-length: 0");
    }

    #[test]
    fn rejects_clean_headers() {
        assert_clean("Set-Cookie: evil=true");
        assert_clean("Location: /index.php");
        assert_clean("Content-Type: text/html");
    }

    #[test]
    fn rejects_lone_encoded_chars() {
        assert_clean("%0d");
        assert_clean("%0a");
        assert_clean("test%0dend");
        assert_clean("%0d%0d");
    }

    #[test]
    fn rejects_lf_only_newlines() {
        assert_clean("foo\nContent-Type: text/html");
        assert_clean("foo\nLocation: /x");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("foo\r\nContent-Type text/html");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
        assert_clean("\r\n");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("这是一段正常文本，无注入");
    }
}
