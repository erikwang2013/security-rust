// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 分隔符混用：一层解析器把 `;` 当分隔符、另一层不当，于是 `?a=1&b=2;c=3`
// 在第一层是 3 个参数、第二层只有 2 个（b 的值变成 "2;c=3"）。纯 `;` 分隔
// 而全程无 `&` 不算污染——所有解析器结论一致，报了就是误杀。
//
// 两条约束防止把正常串打进来：
//   1. 值里排除 `?`：`/app;jsessionid=abc?p=1&q=2` 的 `?` 之后才是查询串，
//      前面的 `;jsessionid=` 是路径上的矩阵参数，不是分隔符混用。
//   2. 混用的 `;k=v` 必须是一个完整参数（后面紧跟 `&` 或到串尾）。后面还接着
//      空格/别的内容说明这不是查询串——`GET /a?x=1&y=2;z=3 HTTP/1.1` 是请求行，
//      `;z=3` 后面跟着的是协议版本。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)&[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200};[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200}(?:&|$)").unwrap(),
        Regex::new(r"(?i);[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200}&[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200}(?:&|$)").unwrap(),
    ]
});

/// `;jsessionid=` 是 Java 容器的矩阵参数（URL 重写会话 ID）。出现它就说明这一层
/// 的 `;` 是路径分隔符而非参数分隔符——只保留重复 key 判定，混用形态不再报。
fn has_matrix_session(input: &str) -> bool {
    const NEEDLE: &[u8] = b";jsessionid=";
    input.as_bytes().windows(NEEDLE.len()).any(|w| w.eq_ignore_ascii_case(NEEDLE))
}

/// 同一 key 重复出现的位置。`regex` crate 无反向引用，纯正则表达不了
/// "两个 key 相等"——只能退化成"任意两个参数"，那 `a=1&b=2` 也会报。
/// 所以这里显式拆参比对。
fn duplicate_key(input: &str) -> Option<(usize, usize)> {
    // ponytail: 只扫前 64 个参数，防超长输入退化成 O(n²)，真实请求够用
    const MAX_TOKENS: usize = 64;

    let mut keys: Vec<&str> = Vec::new();
    let mut token_start = 0usize;

    for (i, token) in input.split(['&', ';']).enumerate() {
        let start = token_start;
        token_start = start + token.len() + 1; // 分隔符恒为单字节 ASCII
        if i >= MAX_TOKENS {
            break;
        }
        let Some(eq) = token.find('=') else {
            continue;
        };
        // `?id=1&id=2`、`/p?id=1&id=2`：首个 key 挂着查询串标记或路径，先剥掉
        let raw = &token[..eq];
        let key_head = raw.rfind(['?', '#']).map_or(0, |p| p + 1);
        let tail = &raw[key_head..];
        let key = tail.trim();
        if key.is_empty() {
            continue;
        }
        if keys.contains(&key) {
            let lead = tail.len() - tail.trim_start().len();
            let at = start + key_head + lead;
            return Some((at, key.len()));
        }
        keys.push(key);
    }
    None
}

pub struct HttpParameterPollutionDetector;

impl Detector for HttpParameterPollutionDetector {
    fn name(&self) -> &'static str {
        "hpp"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        if let Some((offset, len)) = duplicate_key(input) {
            return Some(DetectionResult {
                attack_type: self.name().to_string(),
                category: AttackCategory::Protocol,
                severity: Severity::Medium,
                matched_pattern: input[offset..offset + len].to_string(),
                offset,
                message: "HTTP parameter pollution detected".into(),
            });
        }
        if has_matrix_session(input) {
            return None;
        }
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::Medium, "HTTP parameter pollution detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> HttpParameterPollutionDetector {
        HttpParameterPollutionDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Protocol, Severity::Medium);
    }

    #[test]
    fn name_is_hpp() {
        assert_eq!(det().name(), "hpp");
    }

    #[test]
    fn detects_repeated_key() {
        for input in [
            "a=1&a=2",
            "?id=1&id=2",
            "id=1&id=2&id=3",
            "user=admin&user=guest",
            "a=1&b=2&a=3",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_repeated_array_key() {
        for input in [
            "a[]=1&a[]=2",
            "ids[]=1&ids[]=2&ids[]=3",
            "?filter[role]=admin&filter[role]=user",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_mixed_delimiters() {
        for input in [
            "a=1&b=2;c=3",
            "a=1;b=2&c=3",
            "?x=1&y=2;z=3",
            "a=1&b=2;c=3&d=4",
            "a=1;b=2&c=3&d=4",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn ignores_distinct_keys() {
        // 关键误报防护：不同 key 的正常查询串一律不报
        for input in [
            "a=1&b=2",
            "?page=2&size=20&sort=name",
            "user=admin&pass=123",
            "a=1&b=2&c=3&d=4",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn ignores_matrix_parameter_and_request_line() {
        // `;jsessionid=` 是路径上的矩阵参数——`?` 之前的部分不是查询串
        assert_clean(&det(), "http://x.com/app;jsessionid=ABC123?p=1&q=2");
        assert_clean(&det(), "http://x.com/app;JSESSIONID=ABC123?p=1&q=2");
        assert_clean(&det(), "http://x.com/app;jsessionid=ABC123&p=1");
        // 请求行：`;z=3` 后面跟着协议版本，不是完整参数
        assert_clean(&det(), "GET /a?x=1&y=2;z=3 HTTP/1.1");
        // 混用的 `;k=v` 后面还有别的东西 = 散文
        assert_clean(&det(), "a=1&b=2;c=3 说明");
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "q=donation=5",
            "q=2024--2025",
            "a=1;b=2",
            "Content-Type: multipart/mixed; boundary=abc123",
            "1 & 1 == 2",
            "a + b; c + d",
            "name=John Doe",
            "穿越之霸道总裁爱上我--重生之都市修仙",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "&");
        assert_clean(&det(), "&=");
        // 空 key 不进比对
        assert_clean(&det(), "=1&=2");
        // 第二个 key 没有 `=value`，不进比对
        assert_clean(&det(), "a=1&a");
        // 查询串标记不算 key 的一部分
        assert_hit("?id=1&id=2");
        assert_hit("/p?id=1&id=2");
        assert_hit("http://h/p?id=1&id=2");
        // 空值但 key 重复，仍算污染
        assert_hit("a=&a=");
        // 重复 key 的结果要能对上原文切片
        let r = det().detect("?x=1&y=2&x=3").expect("expected detection");
        assert_eq!(
            &"?x=1&y=2&x=3"[r.offset..r.offset + r.matched_pattern.len()],
            r.matched_pattern
        );
        assert_eq!(r.matched_pattern, "x");
    }
}
