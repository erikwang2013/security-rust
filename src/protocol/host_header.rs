// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

// 正常 HTTP/1.1 请求必然带一个 Host 头，"出现 Host 头"零信息量，曾让每个正常请求
// （`GET /index.html HTTP/1.1\r\nHost: example.com\r\n…`）都吃一个 High —— 单条
// High 就是 40 分，到拒收线。真正的信号是**两个** Host 头：RFC 7230 §5.4 要求含
// 多个 Host 的请求一律回 400，两个解析器取值不一致，这正是主机头攻击
// （路由/缓存投毒、密码重置链接投毒）的落点。
static STRONG_PATTERNS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|\r\n)\s*Host:[^\r\n]*\r\n\s*Host:").unwrap());

// `X-Forwarded-Host` / `X-Original-URL` / `X-Rewrite-URL` 是攻击者覆盖主机判定、
// 绕过前置访问控制的自定义头，但**出现**本身不是攻击——它们同样由代理自己加：
//   * `X-Forwarded-Host`：Traefik 默认就加，nginx 的
//     `proxy_set_header X-Forwarded-Host $host;` 也是常见配置；
//   * `X-Original-URL` / `X-Rewrite-URL`：IIS ARR / Sitecore 这类重写代理会加，
//     代理的用途是让上游知道改写前的原始路径。
// 客户端伪造与代理添加在字节层面完全一致，正则分不开（要判只能判值），所以报 Low：
// 仍然命中，但不单独触发拒绝，也不参与"多条 Medium 叠加成 High"。
// `X-Forwarded-For` / `X-Forwarded-Proto` 连弱档都不进——它们几乎每个走代理的请求
// 都有，判断 XFF 的伪造要看**值**（内网/回环地址、与对端地址矛盾）。
// 三条模式合成一条 alternation：一次 `find` 扫完三条分支，而不是逐条 `find` 各扫一遍
// （干净输入上每条模式都要走到串尾，条数直接乘在开销上）。
// `(?i)` 为三条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的全部分支），
// 与逐条编译时每条各自带 `(?i)` 等价。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\r\n.*X-Forwarded-Host|\r\n.*X-Original-URL|\r\n.*X-Rewrite-URL").unwrap()
});

pub struct HostHeaderDetector;

impl Detector for HostHeaderDetector {
    fn name(&self) -> &'static str {
        "host_header"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::High,
            "Host header attack detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Protocol,
                Severity::Low,
                "Host override header present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        assert_hit_at(input, Severity::High);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(
            &HostHeaderDetector,
            input,
            AttackCategory::Protocol,
            severity,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&HostHeaderDetector, input);
    }

    #[test]
    fn name_is_host_header() {
        assert_eq!(HostHeaderDetector.name(), "host_header");
    }

    #[test]
    fn detects_x_forwarded_host() {
        // 弱档：伪造形态仍然命中，只是不再单独越线（见下面的代理链路样例）
        assert_hit_at(
            "Host: example.com\r\nX-Forwarded-Host: evil.com",
            Severity::Low,
        );
    }

    #[test]
    fn detects_duplicate_host_line() {
        // 单个 Host 头是正常请求，两个才是攻击信号（RFC 7230 §5.4：多个 Host → 400）
        assert_detected("Host: example.com\r\nHost: evil.com");
        assert_detected("GET / HTTP/1.1\r\nHost: a.com\r\nHost: evil.com");
        // 折行（obs-fold）夹在中间也算相邻两行
        assert_detected("GET / HTTP/1.1\r\nHost: a.com\r\n Host: evil.com");
    }

    #[test]
    fn detects_x_original_url() {
        assert_hit_at("Host: a.com\r\nX-Original-URL: /admin", Severity::Low);
    }

    #[test]
    fn detects_x_rewrite_url() {
        assert_hit_at("Host: a.com\r\nX-Rewrite-URL: /admin", Severity::Low);
    }

    #[test]
    fn detects_x_forwarded_host_only() {
        // 同族里只有 `X-Forwarded-Host` 是主机欺骗的载体。`X-Forwarded-For` /
        // `X-Forwarded-Proto` 是代理自己加的，见下面的代理链路负样例。
        assert_hit_at("Host: a.com\r\nX-Forwarded-Host: evil.com", Severity::Low);
    }

    #[test]
    fn detects_mixed_case() {
        assert_hit_at(
            "host: example.com\r\nx-forwarded-host: evil.com",
            Severity::Low,
        );
    }

    /// 代理链路正样例：这些头是**代理自己加的**，请求正常。
    /// 判 High 时每一条都是 40 分、直接拒收——误杀的是整条代理链路。
    /// 弱档下仍然命中（不静默漏报），但单条 5 分越不过拒收线。
    #[test]
    fn proxied_requests_hit_only_the_weak_tier() {
        for req in [
            // Traefik 默认转发头；nginx 的 `proxy_set_header X-Forwarded-Host $host;`
            "GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-Host: app.example.com\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n",
            // 重写代理（IIS ARR / Sitecore）：让上游知道改写前的原始路径
            "GET /private HTTP/1.1\r\nHost: app.example.com\r\nX-Original-URL: /index.html\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n",
        ] {
            assert_hit_at(req, Severity::Low);
        }
    }

    #[test]
    fn rejects_single_header_lines() {
        assert_clean("Host: example.com");
        assert_clean("X-Forwarded-Host: evil.com");
        assert_clean("Host: example.com\r\nAccept: */*");
    }

    /// 现实语料：正常请求只带一个 Host 头。缺了这一组，才会让每个正常请求
    /// （`GET /index.html HTTP/1.1\r\nHost: example.com\r\n…`）都吃一个 High。
    /// 带 `X-Forwarded-Host` / `X-Original-URL` / `X-Rewrite-URL` 的代理请求
    /// 见 `proxied_requests_hit_only_the_weak_tier`。
    #[test]
    fn rejects_well_formed_requests() {
        for req in [
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n",
            "POST /upload HTTP/1.1\r\nHost: upload.example.com\r\nContent-Type: multipart/form-data; boundary=----x\r\nContent-Length: 1234\r\n\r\n",
            // 两段请求连排的日志粘贴：各自带一个 Host，不是重复头
            "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\n",
            // 代理链路：反代 / 负载均衡自己加的头。几乎每个走代理的正常请求都带，
            // 判定的只能是值（内网/回环、与对端地址矛盾），不是头在不在。
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n",
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.7, 10.0.0.1\r\nX-Forwarded-Proto: https\r\nX-Real-IP: 203.0.113.7\r\n\r\n",
        ] {
            assert_clean(req);
        }
        // 普通文档 / 散文 / 查询串
        assert_clean("The report was generated with SYSTEM \"production\" settings.");
        assert_clean("Please cc: ops@example.com on the reply.");
        assert_clean("/search?tag=rust&tag=security&page=2");
    }

    #[test]
    fn rejects_lf_only_newlines() {
        assert_clean("Host: example.com\nX-Forwarded-Host: evil.com");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("主机头示例，无攻击");
    }
}
