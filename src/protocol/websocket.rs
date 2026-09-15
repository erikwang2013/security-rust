// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity};

/// CSWSH 信号：`Origin: null`。
///
/// 浏览器从沙箱 iframe、`data:` URL、部分跨域重定向场景发出的请求会带这个值。
/// 单独出现不足以判定（某些代理会剥离 Origin，部分合法前端也这么发），
/// 必须与 WebSocket 升级同时出现才算。
static ORIGIN_NULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Origin:\s*null").unwrap());

/// WebSocket 升级头。
///
/// **这是合法握手的必需头，单独出现绝不是攻击** —— 本检测器不使用单独命中。
static UPGRADE_WS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Upgrade:\s*websocket").unwrap());

/// WebSocket SSRF：`ws://` 指向环回、私网或链路本地地址。
///
/// 其中 `169.254.169.254` 是云元数据服务端点，是最常被用来窃取实例凭据的目标。
/// 这里只匹配非公网目标，`ws://example.com` 不报。
static WS_INTERNAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)ws://(?:127\.|localhost|0\.0\.0\.0|\[::1\]|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)",
    )
    .unwrap()
});

/// WebSocket 攻击检测器。
///
/// **设计修正（重要）**：本检测器此前把 `Upgrade: websocket`、`Sec-WebSocket-Key:`、
/// `ws://` 当作攻击特征，而前两者是**合法握手的必需头**、后者在正常内容里随处可见 ——
/// 结果是任何合法的 WebSocket 握手都会被判 `Severity::High`，接入阻断路径会打死
/// 整个 WebSocket 业务。现已收窄为两个真正有信号的形态：
///
/// 1. **CSWSH（跨站 WebSocket 劫持）**：`Origin: null` 与 WebSocket 升级同时出现。
///    这两者需要合取判断，正则表达不了（`regex` crate 无 lookahead），故在
///    `detect` 里分两步匹配。
/// 2. **WebSocket SSRF**：`ws://` 指向环回 / 私网 / 链路本地地址（含云元数据端点
///    `169.254.169.254`）。
pub struct WebSocketDetector;

impl Detector for WebSocketDetector {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        let (matched, offset, message) = if let Some(m) = WS_INTERNAL.find(input) {
            (
                m.as_str(),
                m.start(),
                "WebSocket SSRF: handshake targets a loopback/private address",
            )
        } else {
            // CSWSH 需要两个条件同时成立，且顺序不限（Origin 可能在升级头之前或之后）
            let origin = ORIGIN_NULL.find(input);
            let upgrade = UPGRADE_WS.find(input);
            match (origin, upgrade) {
                (Some(o), Some(_)) => (
                    o.as_str(),
                    o.start(),
                    "WebSocket hijack attempt (cross-site WebSocket hijacking): Origin: null on a WebSocket upgrade",
                ),
                _ => return None,
            }
        };

        Some(DetectionResult {
            attack_type: self.name().to_string(),
            category: AttackCategory::Protocol,
            severity: Severity::High,
            matched_pattern: matched.to_string(),
            offset,
            message: message.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &WebSocketDetector,
            input,
            AttackCategory::Protocol,
            Severity::High,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&WebSocketDetector, input);
    }

    #[test]
    fn name_is_websocket() {
        assert_eq!(WebSocketDetector.name(), "websocket");
    }

    #[test]
    fn detects_origin_null_with_upgrade() {
        assert_detected("Origin: null\r\nUpgrade: websocket");
        assert_detected("Upgrade: websocket\r\nOrigin: null");
        assert_detected(
            "GET /chat HTTP/1.1\r\nOrigin: null\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc==",
        );
    }

    #[test]
    fn detects_origin_null_case_insensitive() {
        assert_detected("origin: NULL upgrade: WebSocket");
    }

    #[test]
    fn detects_ws_to_loopback_and_private() {
        assert_detected("ws://127.0.0.1:8080/socket");
        assert_detected("ws://localhost/admin");
        assert_detected("ws://[::1]/x");
        assert_detected("ws://0.0.0.0/");
        assert_detected("ws://192.168.1.1/metrics");
        assert_detected("ws://10.0.0.5/internal");
        assert_detected("ws://172.16.0.1/");
        assert_detected("ws://172.31.255.254/");
    }

    #[test]
    fn detects_ws_to_cloud_metadata() {
        // 链路本地地址同时是云元数据端点 —— 窃取实例凭据最常见的路径
        assert_detected("ws://169.254.169.254/latest/meta-data/");
    }

    #[test]
    fn rejects_legitimate_websocket_handshake() {
        // 这几条是合法握手的必需头。此前它们会被判 High —— 接进阻断路径
        // 会打死整个 WebSocket 业务。本检测器不再单独命中它们。
        assert_clean("Upgrade: websocket");
        assert_clean("upgrade: WebSocket");
        assert_clean("Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
        assert_clean("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
        assert_clean("SEC-WEBSOCKET-KEY: abc==");
        assert_clean(
            "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13",
        );
        assert_clean("Origin: https://example.com\r\nUpgrade: websocket");
    }

    #[test]
    fn rejects_public_ws_targets() {
        assert_clean("ws://example.com/socket");
        assert_clean("ws://evil.com/socket");
        assert_clean("wss://example.com/socket");
        assert_clean("ws://172.15.0.1/x");
        assert_clean("ws://172.32.0.1/x");
    }

    #[test]
    fn rejects_origin_null_alone() {
        // 单个 Origin: null 不足以判定 —— 某些代理会剥离 Origin
        assert_clean("Origin: null");
        assert_clean("Origin: null\r\nHost: example.com");
    }

    #[test]
    fn rejects_benign_requests() {
        assert_clean("Upgrade: h2c");
        assert_clean("Sec-WebSocket-Protocol: chat");
        assert_clean("Origin: https://example.com");
        assert_clean("GET /chat HTTP/1.1\r\nConnection: keep-alive");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("WebSocket 握手信息");
    }
}
