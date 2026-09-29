// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

// 走私要的是"两个解析器读法不同"，所以判定条件必须有第二个信号：
//
//   1. 重复的 Transfer-Encoding 头 —— 取第一个还是最后一个，解析器之间不一致。
//      `\s*` 让头名与冒号之间夹空白的形态也进重复判定。
//   2. 头名与冒号之间夹空白 —— RFC 7230 §3.2.4 明确禁止，正常客户端不会发，
//      宽松解析器却照收并当作 chunked，这正是绕过前面这条的手法。
//
// 单独的 `Transfer-Encoding: chunked` 不是信号：它是带 chunked 请求体的正常请求的
// 常规写法。原第二条正则 (`Transfer-Encoding:[\s]*chunked`) 把它判成 High，
// 于是一个正常的 POST 光靠这一条加上 host_header / header_injection 就凑满
// 3 个 High（score 120）被整条拒掉。
// 两条模式合成一条 alternation：干净输入上每条模式都要走到串尾，模式条数直接乘在
// 单次 `find` 的开销上；合并后一次扫描扫完两条分支。
// `(?i)` 为两条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的全部分支），
// 与逐条编译时每条各自带 `(?i)` 等价。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Transfer-Encoding\s*:.*\r\n.*Transfer-Encoding\s*:|Transfer-Encoding\s+:")
        .unwrap()
});

pub struct RequestSmugglingDetector;

impl Detector for RequestSmugglingDetector {
    fn name(&self) -> &'static str {
        "request_smuggling"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::High,
            "HTTP request smuggling detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &RequestSmugglingDetector,
            input,
            AttackCategory::Protocol,
            Severity::High,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&RequestSmugglingDetector, input);
    }

    #[test]
    fn name_is_request_smuggling() {
        assert_eq!(RequestSmugglingDetector.name(), "request_smuggling");
    }

    #[test]
    fn detects_duplicate_transfer_encoding() {
        assert_detected("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity");
        // 头名与冒号之间夹空白：两个解析器取不同分支，同样要报（旧正则漏报）
        assert_detected("Transfer-Encoding : chunked\r\nTransfer-Encoding : identity");
        assert_detected("Transfer-Encoding : chunked\r\nTransfer-Encoding: identity");
    }

    #[test]
    fn detects_obfuscated_transfer_encoding() {
        // RFC 7230 §3.2.4 禁止头名与冒号之间有空白。正常客户端不发这种头，
        // 宽松解析器却当作 chunked —— 单独出现即判定，与大小写无关。
        assert_detected("Transfer-Encoding : chunked");
        assert_detected("transfer-encoding : CHUNKED");
        assert_detected("Transfer-Encoding\t: chunked");
    }

    #[test]
    fn rejects_well_formed_transfer_encoding() {
        // 带 chunked 请求体的正常请求就是这样发的。空格的多少、大小写都不构成信号，
        // 第二个信号（重复头 / 头名夹空白）才构成。整条正常请求必须干净。
        for input in [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:chunked",
            "Transfer-Encoding:\tchunked",
            "transfer-encoding: CHUNKED",
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: multipart/form-data; boundary=----x\r\nContent-Length: 1234\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert_clean(input);
        }
    }

    #[test]
    fn rejects_benign_headers() {
        assert_clean("Content-Length: 5\r\nContent-Length: 10");
        assert_clean("Transfer-Encoding: gzip");
        assert_clean("Connection: keep-alive");
    }

    #[test]
    fn rejects_missing_colon() {
        assert_clean("Transfer-Encoding chunked");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("Transfer-Encoding: chuncked");
    }

    /// 现实语料：不含 TE 头的正常文本不该有任何命中
    #[test]
    fn rejects_real_world_text() {
        assert_clean("The report was generated with SYSTEM \"production\" settings.");
        assert_clean("Please cc: ops@example.com on the reply.");
        assert_clean("/search?tag=rust&tag=security&page=2");
        assert_clean(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" ",
            "\"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M4 4h16v16H4z\"/></svg>"
        ));
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("普通请求体，无攻击特征");
    }
}
