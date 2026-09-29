// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

/// 弱信号：`Host:` 头里出现内网 / 环回地址。
///
/// 这一族只有「出现」这一个判据，而且它在正常流量里是**常态**，不是异常：
///
/// - k8s 里按 Pod IP 互调：`Host: 10.244.1.5:8080`（每一个 pod 间请求都是这个形状）
/// - 容器网络：`Host: 172.18.0.2:3000`
/// - 局域网设备（路由器管理页、NAS、打印机）：`Host: 192.168.1.1`
/// - 健康检查与开发服务：`Host: localhost:8000`、`Host: 127.0.0.1`
///
/// 这些请求都来自内网，而**真正的 rebinding 恰恰看的是「公网域名 + 解析结果指向
/// 内网」**：浏览器发出去的是 `Host: attacker.example`，内网服务收到的也正是这个名字。
/// 单条字符串里看不到解析历史，换句话说本检测器测的形态与攻击形态并不重合，
/// 收紧无从谈起（收紧成什么样都还是「内网地址出现」）。所以报 Low：仍然检出，
/// 由调用方按聚合分决定 —— 单条 5 分不越过拒绝线，一堆弱信号叠加才可能升级。
// 七条同档模式合成一条 alternation：一次 `find` 扫完，而不是逐条 `find` 各扫一遍
// （干净输入上每条模式都要走到串尾，条数直接乘在开销上）。
// `(?i)` 为全部七条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的全部分支），
// 与逐条编译时每条各自带 `(?i)` 等价。各分支的完整文本未变，条数从 7 降到 1。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)Host:\s*127\.|Host:\s*10\.|Host:\s*192\.168\.|Host:\s*172\.(1[6-9]|2\d|3[01])|Host:\s*localhost|Host:\s*\[::1\]|Host:\s*0\.0\.0\.0",
    )
    .unwrap()
});

pub struct DnsRebindingDetector;

impl Detector for DnsRebindingDetector {
    fn name(&self) -> &'static str {
        "dns_rebinding"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*WEAK_PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::Low,
            "DNS rebinding signal: Host header names a private address (weak signal)",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本检测器整体是弱信号：检出即 `Low`，单独一条不越过拒绝线。
    fn assert_low(input: &str) {
        crate::test_helpers::assert_detected(
            &DnsRebindingDetector,
            input,
            AttackCategory::Protocol,
            Severity::Low,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&DnsRebindingDetector, input);
    }

    #[test]
    fn name_is_dns_rebinding() {
        assert_eq!(DnsRebindingDetector.name(), "dns_rebinding");
    }

    #[test]
    fn detects_loopback_host() {
        assert_low("Host: 127.0.0.1");
    }

    #[test]
    fn detects_private_hosts() {
        assert_low("Host: 10.0.0.2");
        assert_low("Host: 192.168.1.1");
        assert_low("Host: 172.16.0.1");
        assert_low("Host: 172.31.255.255");
    }

    #[test]
    fn detects_local_names() {
        assert_low("Host: localhost");
        assert_low("Host: [::1]");
        assert_low("Host: 0.0.0.0");
    }

    #[test]
    fn detects_mixed_case() {
        assert_low("host: 127.0.0.1");
    }

    /// 反向对照：这些是内网流量的**常态**形状 —— 按 Pod IP 互调的 k8s 集群、
    /// docker compose 网络、局域网路由器，每个请求都长这样。降档前它们全判 High，
    /// 接入阻断路径等于打死整个内网业务。
    #[test]
    fn intranet_host_headers_are_weak_not_high() {
        for input in [
            "GET /healthz HTTP/1.1\r\nHost: 10.244.1.5:8080\r\n\r\n",
            "POST /v1/items HTTP/1.1\r\nHost: 172.18.0.2:3000\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n",
            "GET /metrics HTTP/1.1\r\nHost: localhost:8000\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        ] {
            assert_low(input);
        }
    }

    /// 语料里的正常请求（公网 Host + 代理头）仍然干净。
    #[test]
    fn proxied_public_request_is_clean() {
        assert_clean(
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n",
        );
    }

    #[test]
    fn rejects_public_hosts() {
        assert_clean("Host: example.com");
        assert_clean("Host: 8.8.8.8");
        assert_clean("Host: 172.32.0.1");
    }

    #[test]
    fn rejects_hostname_variants() {
        assert_clean("Hostname: 127.0.0.1");
        assert_clean("Hostname: localhost");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("Host: 12.7.0.1");
        assert_clean("Host: 172.15.0.1");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("主机名解析测试，无攻击");
    }
}
