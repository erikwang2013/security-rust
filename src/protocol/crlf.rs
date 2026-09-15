// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 与 MailHeaderDetector 的分工：那边看邮件头（Bcc:/From:/MIME），
// 这边专看 HTTP 响应拆分——CRLF 之后紧跟响应头，等于让攻击者自己写响应。
// 顺序按"信息量"排：命中越具体的形态越先返回。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // 双 CRLF：响应头结束、开始注入响应体
        Regex::new(r"(?i)%0d%0a%0d%0a").unwrap(),
        // 编码 CRLF + 响应头
        Regex::new(r"(?i)%0d%0a(?:set-cookie|location|content-length|content-type|refresh|status|www-authenticate)\s*:").unwrap(),
        // 裸 CRLF + 响应头
        Regex::new(r"(?i)\r\n(?:set-cookie|location|content-length|content-type|refresh|status|www-authenticate)\s*:").unwrap(),
        // 裸 LF 变体（部分服务端只按 \n 断行）
        Regex::new(r"(?i)\n(?:set-cookie|location|content-length|refresh)\s*:").unwrap(),
        // 反序编码对 %0a%0d
        Regex::new(r"(?i)%0a%0d").unwrap(),
        // 单个编码 CRLF
        Regex::new(r"(?i)%0d%0a").unwrap(),
    ]
});

pub struct CrlfInjectionDetector;

impl Detector for CrlfInjectionDetector {
    fn name(&self) -> &'static str {
        "crlf_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::High, "CRLF/HTTP response splitting detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> CrlfInjectionDetector {
        CrlfInjectionDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Protocol, Severity::High);
    }

    #[test]
    fn name_is_crlf_injection() {
        assert_eq!(det().name(), "crlf_injection");
    }

    #[test]
    fn detects_encoded_crlf() {
        for input in [
            "test%0d%0aSet-Cookie: evil=true",
            "%0d%0a",
            "foo%0D%0Abar",
            "%0a%0d",
            "a%0d%0a%0d%0a<script>alert(1)</script>",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_response_splitting_with_headers() {
        for input in [
            "value%0d%0aLocation: http://evil.com",
            "value%0d%0aContent-Length: 0",
            "value%0d%0aContent-Type: text/html",
            "value%0d%0aSet-Cookie: session=evil",
            "value%0d%0aRefresh: 0;url=http://evil.com",
            "value\r\nSet-Cookie: session=evil",
            "value\r\nLocation: http://evil.com",
            "value\nContent-Length: 0",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn matched_pattern_points_at_the_crlf() {
        let input = "value%0d%0aLocation: http://evil.com";
        let r = det().detect(input).expect("expected detection");
        assert!(r.matched_pattern.contains("%0d%0a"));
        assert_eq!(&input[r.offset..r.offset + r.matched_pattern.len()], r.matched_pattern);
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "line one\r\nline two",
            "line one\nline two",
            "Host: example.com\r\nAccept: text/html",
            "Set-Cookie: a=b",
            "Location: http://example.com",
            "a%20b",
            "100%25",
            "url: http://example.com/a?b=c&d=e",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "\r\n");
        assert_clean(&det(), "%0d");
        assert_clean(&det(), "%0a");
        // 前缀相近但非响应头
        assert_clean(&det(), "value\r\nSet-Cookies: a=b");
        assert_clean(&det(), "value\r\nContent-Lengthy: a=b");
    }
}
