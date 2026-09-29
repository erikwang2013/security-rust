// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

/// 强信号：攻击形态受约束 —— 内网目标出现在 **URL authority 位置**（`//` 之后），
/// 或者字面量本身就是只为 SSRF 存在的东西（云元数据端点、危险协议）。
///
/// 为什么内网字面量要求 `//` 前缀：SSRF 的载荷一定是「往哪发」，即 URL；
/// 而同一个 `10.0.0.5` 出现在配置、日志、代理头里时是基础设施的日常词汇 —
/// 内网 LB 加的 `X-Forwarded-For: 10.0.0.5`、k8s 按 Pod IP 互调的
/// `Host: 10.244.1.5:8080`、docker 网络的 `172.18.0.2`。
/// 非 URL 位置的那一份降为弱信号（见 `WEAK_PATTERNS`），不删除。
// 十三条同档模式合成一条 alternation：干净输入上每条模式都要走到串尾，条数直接乘在
// 单次 `find` 的开销上；合并后一次扫描扫完十三条分支。各分支的完整文本未变，只多了 `|`。
// `(?i)` 为十三条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的全部分支），
// 与逐条编译时每条各自带 `(?i)` 等价。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            // 云元数据：地址与它的 GCP 域名等价物。任何正常内容里都不该出现，
            // 且没有「配置写法」——所以这一条不要求 URL 上下文。
            r"(?i)169\.254\.169\.254",
            r"|metadata\.google\.internal",
            r"|//10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"|//172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
            r"|//192\.168\.\d{1,3}\.\d{1,3}",
            // 段数放宽到 2~4：`127.1` / `127.0.0.1` 都指向环回。
            r"|//127\.\d{1,3}(?:\.\d{1,3}){0,2}",
            // 主机名形态的环回只在 URL authority 位置认（`//localhost`），与 websocket.rs 的
            // `ws://(?:...|localhost|...)` 同一口径。裸 `localhost` 会把
            // `mongodb://user@localhost:27017/db` 这类连接串也判成 Critical —— 那是 data_leak
            // 的地盘，scanner 里 ssrf 排在 data_leak 前面，会把它的结果顶掉。
            // 代价（已知缺口）: `http://user@localhost/` 带 userinfo 的、以及无 scheme 的
            // `localhost:8080/` 认不出来 —— websocket.rs 的 `ws://user@localhost` 同样漏。
            r"|//localhost\b",
            // `0.0.0.0` / `[::1]` 同理：只在 URL authority 位置认。
            // 裸形态是配置里的**监听地址** —— `listen 0.0.0.0:80;`（nginx 默认站点）、
            // `app.run(host="0.0.0.0")`（Flask 教程）、`bind 0.0.0.0`（redis.conf）、
            // `listen [::1]:8080;` —— 全是正常内容。
            r"|//0\.0\.0\.0",
            r"|//\[::1\]",
            r"|gopher://",
            r"|dict://",
            r"|ftp://[^/]*@",
            r"|file:///",
        ]
        .concat(),
    )
    .unwrap()
});

/// 弱信号：内网 / 环回字面量出现在**非 URL 位置**。
///
/// 同一串字节在两种上下文里含义相反，而正则只看得见字节：
/// - 攻击侧：`{"host": "10.0.0.1", "port": 6379}` —— 目标主机与端口分开传的 SSRF
/// - 正常侧：`X-Forwarded-For: 10.0.0.5`（内网 LB 加的）、`Host: 10.244.1.5`（k8s）、
///   `bind 127.0.0.1`（redis.conf 默认值）、`127.0.0.1 localhost`（/etc/hosts）
///
/// 分不开，所以报 Low：仍然检出，单条 5 分不越过拒绝线，聚合分交给调用方。
// 六条同档模式合成一条 alternation，理由与 `STRONG_PATTERNS` 相同：条数从 6 降到 1。
// 分支顺序与文本都与逐条时一致。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            r"(?i)10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
            r"|192\.168\.\d{1,3}\.\d{1,3}",
            r"|127\.\d{1,3}(?:\.\d{1,3}){0,2}",
            r"|0\.0\.0\.0",
            r"|\[::1\]",
        ]
        .concat(),
    )
    .unwrap()
});

// 已知缺口（有意保留，别当 bug 修）：
//
// 1. 环回的进制/映射变形 —— 十进制 `2130706433`、八进制 `0177.0.0.1`、十六进制
//    `0x7f.0.0.1`、IPv6 映射 `::ffff:127.0.0.1` —— 都要先把字面量归一化再比范围，
//    正则做不了这件事。只匹配字面量是本检测器的设计边界。
// 2. 非 URL 位置的内网字面量只到 `Severity::Low`（见 `WEAK_PATTERNS`）：
//    `{"host": "10.0.0.1", "port": 6379}` 这类「主机与端口分开传」的载荷，
//    与 `X-Forwarded-For: 10.0.0.5`、`bind 127.0.0.1` 逐字节同形，靠单条字符串
//    分不开；带 userinfo 的连接串（`postgres://app:pw@10.0.0.5/db`）同理。
//    要提升这一档只能由调用方按聚合分决定。
//
// 详见 docs/OWASP-COVERAGE.md「缺口」一节。
pub struct SsrfDetector;

impl Detector for SsrfDetector {
    fn name(&self) -> &'static str {
        "ssrf"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::Critical,
            "SSRF server-side request forgery detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Protocol,
                Severity::Low,
                "internal address literal present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &SsrfDetector,
            input,
            AttackCategory::Protocol,
            Severity::Critical,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&SsrfDetector, input);
    }

    fn assert_low(input: &str) {
        crate::test_helpers::assert_detected(
            &SsrfDetector,
            input,
            AttackCategory::Protocol,
            Severity::Low,
        );
    }

    #[test]
    fn name_is_ssrf() {
        assert_eq!(SsrfDetector.name(), "ssrf");
    }

    #[test]
    fn detects_cloud_metadata_ip() {
        assert_detected("http://169.254.169.254/latest/meta-data/");
    }

    #[test]
    fn detects_internal_ipv4() {
        assert_detected("http://10.0.0.1/admin");
    }

    #[test]
    fn detects_private_ranges() {
        assert_detected("http://192.168.1.1/");
        assert_detected("http://172.16.0.1/");
        assert_detected("http://172.31.255.255/");
        assert_detected("http://127.0.0.1:8080/");
        assert_detected("http://0.0.0.0/");
        assert_detected("http://[::1]/");
    }

    #[test]
    fn detects_ssrf_uri_schemes() {
        assert_detected("gopher://evil.com/_GET / HTTP/1.1");
        assert_detected("dict://evil.com:11211/");
        assert_detected("ftp://user@evil.com/file");
        assert_detected("file:///etc/passwd");
    }

    #[test]
    fn detects_mixed_case_schemes() {
        assert_detected("GOPHER://evil.com/");
        assert_detected("FILE:///etc/shadow");
    }

    #[test]
    fn detects_loopback_hostname_and_short_forms() {
        assert_detected("http://localhost/admin");
        assert_detected("http://localhost:8080/");
        assert_detected("http://127.1/");
        // JSON 里主机名后面跟的是引号而不是 / 或 :，也要认
        assert_detected(r#"{"url": "http://localhost"}"#);
    }

    #[test]
    fn detects_cloud_metadata_hostname() {
        assert_detected("http://metadata.google.internal/computeMetadata/v1/");
    }

    #[test]
    fn rejects_public_hosts() {
        assert_clean("http://example.com/index.html");
        assert_clean("https://github.com/security-rust");
        assert_clean("http://172.32.0.1/");
        assert_clean("http://8.8.8.8/dns");
    }

    /// 反向对照：收紧 localhost 之后不能把「长得像 localhost」的正常目标也打上
    /// 反向对照：内网字面量出现在**非 URL** 位置时是基础设施的日常词汇。
    /// 收紧前这些全判 Critical（单条即拒绝）——「内网 LB 加代理头」和
    /// 「k8s 按 Pod IP 互调」是生产环境每个请求的默认形状。
    #[test]
    fn bare_internal_literals_are_weak_not_critical() {
        for input in [
            // 内网 LB / 反代自动添加的头
            "GET /api HTTP/1.1\r\nHost: api.internal\r\nX-Forwarded-For: 10.0.0.5\r\nX-Real-IP: 10.0.0.5\r\n\r\n",
            // k8s 按 Pod IP 互调、docker 网络
            "GET /healthz HTTP/1.1\r\nHost: 10.244.1.5:8080\r\n\r\n",
            "POST /v1/items HTTP/1.1\r\nHost: 172.18.0.2:3000\r\n\r\n",
            // 局域网设备
            "GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n",
            // 监听地址：nginx 默认站点、Flask 教程、redis.conf 默认值、/etc/hosts
            "server {\n  listen 0.0.0.0:80;\n}\n",
            "server {\n  listen [::1]:8080;\n}\n",
            "if __name__ == \"__main__\":\n    app.run(host=\"0.0.0.0\", port=5000)\n",
            "bind 127.0.0.1 -::1\nprotected-mode yes\n",
            // 弱层的攻击侧同样在这一档：主机与端口分开传的 SSRF 载荷，
            // 字节上与上面的配置无异，所以只报 Low（仍然检出）
            r#"{"host": "10.0.0.1", "port": 6379}"#,
            // 带 userinfo 的连接串：正常配置（内网 DB 连接串）与绕白名单的 SSRF
            // 载荷逐字节同形 —— `postgres://app:pw@10.0.0.5/db` /
            // `http://user:pass@127.0.0.1/`，同样只报 Low
            "postgres://app:pw@10.0.0.5:5432/db",
            "http://user:pass@127.0.0.1/",
        ] {
            assert_low(input);
        }
    }

    /// 收紧的另一半：URL 上下文里的同一批目标必须照报 Critical。
    #[test]
    fn url_context_internal_targets_stay_critical() {
        for input in [
            "curl http://10.0.0.1:8080/admin",
            "http://192.168.0.10/cgi-bin/status",
            "http://172.20.0.3:9200/_cat/indices",
            "http://127.1/",
            "http://[::1]:9200/",
            "http://0.0.0.0:8080/",
            "gopher://10.0.0.1:6379/_INFO",
        ] {
            assert_detected(input);
        }
    }

    #[test]
    fn rejects_localhost_lookalikes() {
        // 连接串里的 localhost 归 data_leak 管，ssrf 不该抢（authority 前是 userinfo）
        assert_clean("mongodb://admin:password@localhost:27017/db");
        assert_clean("http://internal.example.com/api");
        assert_clean("metadata.google.com 是普通域名");
        assert_clean("localhost 只是文档里的一个词");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("http://10.0.0/admin");
        assert_clean("http://169.254.169/admin");
        assert_clean("ftp://evil.com/pub");
        assert_clean("http://192.168/admin");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
        assert_clean("\t\n");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("你好，世界！这是一个正常的中文文本。");
    }
}
