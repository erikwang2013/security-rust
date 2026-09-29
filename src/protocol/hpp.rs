// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
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
// 两条同档模式合成一条 alternation：一次 `find` 扫完两条分支，而不是逐条 `find` 各扫
// 一遍。`(?i)` 为两条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的分支），
// 与逐条编译时每条各自带 `(?i)` 等价。分支文本未变，条数从 2 降到 1；`detect()` 里的
// 前置判断（无分隔符直接返回、`;jsessionid=` 走弱档）与下面的重复 key 手动判定都不受影响。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            r"(?i)&[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200};[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200}(?:&|$)",
            r"|;[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200}&[a-z0-9_%.\-]{1,64}=[^&;\s?]{0,200}(?:&|$)",
        ]
        .concat(),
    )
    .unwrap()
});

/// `;jsessionid=` 是 Java 容器的矩阵参数（URL 重写会话 ID）。出现它就说明这一层
/// 的 `;` 是路径分隔符而非参数分隔符——只保留重复 key 判定，混用形态不再报。
fn has_matrix_session(input: &str) -> bool {
    const NEEDLE: &[u8] = b";jsessionid=";
    input
        .as_bytes()
        .windows(NEEDLE.len())
        .any(|w| w.eq_ignore_ascii_case(NEEDLE))
}

/// 同一 key 重复出现的位置。`regex` crate 无反向引用，纯正则表达不了
/// "两个 key 相等"——只能退化成"任意两个参数"，那 `a=1&b=2` 也会报。
/// 所以这里显式拆参比对。
///
/// 只按 `&` 拆：`;` 不是查询串的参数分隔符（见文件头注释），按它拆会把
/// `PATH=/usr/bin; PATH=/opt/bin` 这类栈/配置粘贴判成重复 key。
fn duplicate_key(input: &str) -> Option<(usize, usize)> {
    // ponytail: 只扫前 64 个参数，防超长输入退化成 O(n²)，真实请求够用
    const MAX_TOKENS: usize = 64;

    let mut keys: Vec<&str> = Vec::new();
    let mut token_start = 0usize;

    for (i, token) in input.split('&').enumerate() {
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
        // 两个分隔符一个都没有时不可能有参数：重复 key 无从谈起，下面两条正则也都
        // 要求 `&`。超长无分隔符文本（JSON / 正文）实测快 13.8~18.7 倍。
        if !input.contains('&') && !input.contains(';') {
            return None;
        }
        // 强档：分隔符混用。正常查询串不产生这个形状（真实语料 14 条全干净）。
        // `;jsessionid=` 是 Java 容器的矩阵参数，此时这一层的 `;` 是路径分隔符而非
        // 参数分隔符，混用不成立 —— 只保留下面的重复 key 判定。
        if !has_matrix_session(input)
            && let Some(hit) = regex_detect(
                std::slice::from_ref(&*PATTERNS),
                self.name(),
                AttackCategory::Protocol,
                Severity::Medium,
                "HTTP parameter pollution detected",
                input,
            )
        {
            return Some(hit);
        }
        // 弱档：同一 key 出现两次。攻击（`?id=1&id=2`，两层解析器取值不一致）与正常
        // 多值参数（`?tag=rust&tag=web`、`?ids[]=1&ids[]=2`）在字节层面完全一致，
        // 正则分不开 —— 只报 Low：仍然命中，但不单独越线，也不参与
        // "多条 Medium 叠加成 High"。
        duplicate_key(input).map(|(offset, len)| DetectionResult {
            attack_type: self.name().to_string(),
            category: AttackCategory::Protocol,
            severity: Severity::Low,
            matched_pattern: input[offset..offset + len].to_string(),
            offset,
            message: "HTTP parameter pollution detected".into(),
        })
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
        assert_hit_at(input, Severity::Medium);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        assert_detected(&det(), input, AttackCategory::Protocol, severity);
    }

    #[test]
    fn name_is_hpp() {
        assert_eq!(det().name(), "hpp");
    }

    /// 重复 key 是弱档：攻击形态（`?id=1&id=2`）与正常多值参数
    /// （`?tag=rust&tag=web`）逐字节同形，只报 Low —— 仍然命中，不静默漏报。
    #[test]
    fn detects_repeated_key() {
        for input in [
            "a=1&a=2",
            "?id=1&id=2",
            "id=1&id=2&id=3",
            "user=admin&user=guest",
            "a=1&b=2&a=3",
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    #[test]
    fn detects_repeated_array_key() {
        for input in [
            "a[]=1&a[]=2",
            "ids[]=1&ids[]=2&ids[]=3",
            "?filter[role]=admin&filter[role]=user",
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    /// 正常的多值参数：多选框表单、数组参数、文档里的查询串。它们与重复 key 攻击
    /// 同形，所以是弱档命中（5 分）而不是干净 —— 但不能像 Medium 那样参与叠加把
    /// 普通文档推到拒收线（真实语料 `SUPPORT_TICKET` 记的正是这条叠加路径）。
    #[test]
    fn multi_value_params_hit_only_the_weak_tier() {
        for input in [
            "GET /search?tag=rust&tag=web&page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "?ids[]=1&ids[]=2&ids[]=3",
            "https://example.com/log?a=1&a=2",
        ] {
            assert_hit_at(input, Severity::Low);
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

    /// 现实语料：`;` 不是查询串的参数分隔符，栈/配置/散文里的 `;` 与 `=` 同现
    /// 不是污染。缺了这一组才会把 `PATH=/usr/bin; PATH=/opt/bin` 判成 Medium。
    #[test]
    fn ignores_real_world_text() {
        // 环境变量 / 启动参数粘贴（工单里最常见的一类输入）
        assert_clean(&det(), "PATH=/usr/bin; PATH=/opt/bin");
        assert_clean(&det(), "JAVA_HOME=/usr/lib/jvm; JAVA_HOME=/opt/jdk");
        assert_clean(
            &det(),
            "env LANG=zh_CN.UTF-8; JAVA_OPTS=-Xmx2g; JAVA_OPTS=-Dfile.encoding=UTF-8",
        );
        // 源码与散文
        assert_clean(&det(), "for (i=0; i<n; i++) { sum += i; }");
        assert_clean(&det(), "作业：把 a=1; b=2 代入公式，另外 cc: 一下组长。");
        // 正常查询串与它的请求行形态
        assert_clean(&det(), "/search?q=rust&page=2&sort=recent");
        assert_clean(&det(), "GET /search?q=rust&page=2 HTTP/1.1");
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
        assert_hit_at("?id=1&id=2", Severity::Low);
        assert_hit_at("/p?id=1&id=2", Severity::Low);
        assert_hit_at("http://h/p?id=1&id=2", Severity::Low);
        // 空值但 key 重复，仍算污染
        assert_hit_at("a=&a=", Severity::Low);
        // 重复 key 的结果要能对上原文切片
        let r = det().detect("?x=1&y=2&x=3").expect("expected detection");
        assert_eq!(
            &"?x=1&y=2&x=3"[r.offset..r.offset + r.matched_pattern.len()],
            r.matched_pattern
        );
        assert_eq!(r.matched_pattern, "x");
    }
}
