// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

// `Access-Control-Allow-Origin: *` 单独出现是公开 API / 静态资源 / CDN 的常态
// （而且浏览器本来就拒绝它带凭据），静态白名单更是正常配置——都不报。
// 真危险的只有两种可判定的形态：
//   1. 显式 `null` 源——沙箱 iframe、`data:` URL 的源就是 null，服务端一旦回显，
//      它们就能读到带凭据的响应；
//   2. `*` 与 `Credentials: true` 同现——坏配置，浏览器会拒绝，但配置本身是信号。
// 反射型（ACAO 回显请求的 Origin）**故意不判**：白名单命中时回显正是合法实现，
// 只看两个值相等无法把正常动态 CORS 和攻击区分开，判了必然大面积误杀。
static ACAO_NULL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Access-Control-Allow-Origin:\s*null\b").unwrap());
static ACAO_WILDCARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Access-Control-Allow-Origin:\s*\*").unwrap());
static CREDS_TRUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Access-Control-Allow-Credentials:\s*true").unwrap());
static ORIGIN_NULL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Origin:\s*null\b").unwrap());

pub struct CorsDetector;

impl Detector for CorsDetector {
    fn name(&self) -> &'static str {
        "cors"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        // 顺序有讲究：`Access-Control-Allow-Origin: null` 里含有 `Origin: null` 子串，
        // 先判 ACAO 形态，命中时 matched_pattern 才是完整的那一行。
        let m = if let Some(m) = ACAO_NULL.find(input) {
            m
        } else if let Some(m) = ACAO_WILDCARD
            .find(input)
            .filter(|_| CREDS_TRUE.is_match(input))
        {
            m
        } else {
            ORIGIN_NULL.find(input)?
        };
        Some(DetectionResult {
            attack_type: self.name().to_string(),
            category: AttackCategory::Protocol,
            severity: Severity::Medium,
            matched_pattern: m.as_str().to_string(),
            offset: m.start(),
            message: "CORS bypass attempt detected".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &CorsDetector,
            input,
            AttackCategory::Protocol,
            Severity::Medium,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&CorsDetector, input);
    }

    #[test]
    fn name_is_cors() {
        assert_eq!(CorsDetector.name(), "cors");
    }

    #[test]
    fn detects_null_origin() {
        assert_detected("Origin: null");
        assert_detected("Origin:null");
    }

    #[test]
    fn detects_null_allow_origin() {
        assert_detected("Access-Control-Allow-Origin: null");
        assert_detected("Access-Control-Allow-Origin:null");
        // `Origin: null` 是上面的 ACAO 行的子串，匹配到完整那一行而不是片段
        let r = CorsDetector
            .detect("Access-Control-Allow-Origin: null")
            .unwrap();
        assert_eq!(r.matched_pattern, "Access-Control-Allow-Origin: null");
    }

    #[test]
    fn wildcard_alone_is_clean_but_with_credentials_is_not() {
        // 公开 API / 静态资源常态，浏览器也拒绝它带凭据 —— 单独不报
        assert_clean("Access-Control-Allow-Origin: *");
        assert_clean("Access-Control-Allow-Origin:*");
        // `*` + 凭据同现是坏配置，报
        assert_detected("Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true");
        assert_detected("Access-Control-Allow-Origin:*\nAccess-Control-Allow-Credentials:true");
    }

    #[test]
    fn allow_credentials_alone_is_clean() {
        // 与具体白名单源搭配时是正常响应头，单独出现不构成信号
        assert_clean("Access-Control-Allow-Credentials: true");
    }

    #[test]
    fn detects_mixed_case() {
        assert_detected("origin: NULL");
        assert_detected("access-control-allow-origin: null");
        assert_detected("access-control-allow-origin: *\r\naccess-control-allow-credentials: TRUE");
    }

    #[test]
    fn rejects_benign_headers() {
        assert_clean("Origin: http://example.com");
        assert_clean("Access-Control-Allow-Origin: https://example.com");
        assert_clean("Access-Control-Allow-Origin: *");
        assert_clean("Access-Control-Allow-Credentials: false");
        assert_clean("Origin: *");
        // 反射/白名单回显：与请求 Origin 相同的 ACAO 是正常动态 CORS
        assert_clean(
            "Origin: https://example.com\r\nAccess-Control-Allow-Origin: https://example.com",
        );
        // `null` 必须是完整的 token
        assert_clean("Access-Control-Allow-Origin: nullify-me");
    }

    #[test]
    fn rejects_space_before_colon() {
        assert_clean("Access-Control-Allow-Origin : *");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("跨域配置说明，无攻击");
    }
}
