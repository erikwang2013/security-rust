// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

// 三条模式合成一条 alternation：干净输入上每条模式都要走到串尾，条数直接乘在单次
// `find` 的开销上；合并后一次扫描扫完三条分支。各分支的完整文本未变，只多了 `|`。
// `(?i)` 为三条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的全部分支），
// 与逐条编译时每条各自带 `(?i)` 等价。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            // 只留响应专有头。`Content-Length` / `Content-Type` / `Transfer-Encoding` 是
            // 请求头：正常请求的每个头前面都跟着一个 `\r\n`，"CRLF + 请求头名"与正常报文
            // 逐字节同形，判不出来——曾让每个带 body 的 POST 连吃两个 High（单条 High 即
            // 40 分，到拒收线）。这三个头的编码形态由下面两条 `%0d` 模式覆盖
            // （`%0d%0aContent-Length: 0` 仍命中），裸 `\r\n` 形态只能放弃。
            // 响应专有头出现在请求侧没有正常解释，单独出现即异常。
            //
            // 本检测器按**请求侧**设计：喂进来的若是抓包存下的**响应**原文，这一条必然命中
            // （真实响应本来就带 `\r\nSet-Cookie:` / `\r\nLocation:`）。那不是待修的误报——
            // 响应里哪些头是被注入的，只看响应本身分不出来，所以别把"扫响应也命中"当 bug
            // 去放宽这条；要扫响应，该由调用方按来源决定是否采信。
            r"(?i)\r\n\s*(?:Set-Cookie|Location|Refresh|Status|WWW-Authenticate):",
            r"|%0[dD].*%0[aA]",
            // 反序对 LF-CR。部分解析器容忍这个顺序，是响应拆分的绕过变体。
            // 编码形态在正常文本里不出现，误报面与上面那条同量级。
            // （原先由 crlf_injection 覆盖，该检测器因 LF-only 分支误报、其余形态
            // 与本检测器重复而删除，其独有的这几条形态改由这里接手。）
            r"|%0[aA].*%0[dD]",
        ]
        .concat(),
    )
    .unwrap()
});

pub struct HeaderInjectionDetector;

impl Detector for HeaderInjectionDetector {
    fn name(&self) -> &'static str {
        "header_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::High,
            "HTTP header injection (CRLF) detected",
            input,
        )
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
    fn detects_raw_crlf_response_headers() {
        // 裸 CRLF 只在响应专有头上是信号：请求头名（Content-Type 等）与正常报文同形，
        // 放到这里会打死每个带 body 的正常 POST，改由 %0d%0a 形态覆盖（见下）。
        assert_detected("foo\r\nSet-Cookie: evil=true");
        assert_detected("bar\r\nLocation: http://evil.com");
        assert_detected("foo\r\n  Set-Cookie: evil=true");
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

    /// 现实语料：正常报文的每个头前面都跟着 `\r\n`，不带编码形态就不能命中。
    /// 缺了这一组，才会让一个正常 POST（`Content-Type` + `Content-Length`）
    /// 连吃两个 High 被整条拒掉。
    #[test]
    fn rejects_well_formed_requests() {
        for req in [
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n",
            "POST /upload HTTP/1.1\r\nHost: upload.example.com\r\nContent-Type: multipart/form-data; boundary=----x\r\nContent-Length: 1234\r\nTransfer-Encoding: chunked\r\n\r\n",
            // 与正常报文的头行同形的裸 CRLF 形态：请求头名不再构成信号
            "foo\r\nContent-Type: text/html",
            "bar\r\nTransfer-Encoding: chunked",
        ] {
            assert_clean(req);
        }
        assert_clean("The report was generated with SYSTEM \"production\" settings.");
        assert_clean("Please cc: ops@example.com on the reply.");
        assert_clean("/search?tag=rust&tag=security&page=2");
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
