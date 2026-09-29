// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：LDAP 过滤器语法。每条都要求**过滤器的形状**，而不只是标点出现。
///
/// 前三条的旧形态只认标点序列，于是命中了正常代码里的日常写法：
/// `\(\s*&` 命中 rustfmt 的多行调用（`f(\n    &buf,\n)`）、`\(\s*\|` 命中多行
/// 闭包实参（`map(\n    |x| x * 2,\n)`）、`\(!\s*\(` 命中 C/JS 的
/// `if (!(a == b))` —— 三条都是 `Severity::High`，单条即越过拒绝线。
/// LDAP 的 `&`/`|` 后面必然跟一个过滤器（即 `(`），`!` 后面必然是一个属性断言，
/// 按这个形状收紧后误报消失、过滤器照报。
/// 8 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 8 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // (&(…
        r"\(\s*&\s*\(",
        // (|(…
        r"|\(\s*\|\s*\(",
        // (!(attr op value)：op 是单个 `=`（`~=` / `>=` / `<=` 也认），
        // `==` / `!=` 是 C/JS 的相等比较，不是 LDAP。
        r"|\(!\s*\(\s*[a-zA-Z][\w.-]*\s*[~<>]?=[^=]",
        r"|\*\(cn=",
        r"|\(\s*objectClass\s*=",
        r"|\(\s*uid\s*=",
        r"|\)\s*\((?:&|\||!)",
        r"|\(\s*cn\s*=",
    ))
    .unwrap()
});

pub struct LdapInjectionDetector;

impl Detector for LdapInjectionDetector {
    fn name(&self) -> &'static str {
        "ldap_injection"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::High,
            "LDAP injection detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> LdapInjectionDetector {
        LdapInjectionDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::High,
        );
    }

    #[test]
    fn name_is_ldap_injection() {
        assert_eq!(det().name(), "ldap_injection");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "(&(uid=admin)(!(|(cn=*))))",
            "(&(cn=user))",
            "(|(cn=admin))",
            "*(cn=*)",
            "(!(uid=*))",
            "(objectClass=*)",
            ")(&(uid=admin))",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "Please enter your username and password",
            "The directory contains user records",
            "uid=admin",
            "cn=test",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: attribute present but not in filter form
        assert!(det().detect("(uidadmin)").is_none());
        assert!(det().detect("(xuid=1)").is_none());
        assert!(det().detect("user (uid) admin").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in ["(&(UID=admin))", "( uid =*)", "( cn = * )"] {
            assert_hit(input);
        }
    }

    /// 反向对照：LDAP 运算符的**标点序列**在正常代码里是日常写法。
    /// 收紧前这四条全判 High（单条即拒绝）——「`&`/`|` 另起一行」是 rustfmt
    /// 对长参数列表和多行闭包的默认排版，「`!(…)`」是 C/JS 的取反写法。
    #[test]
    fn operators_in_ordinary_code_are_not_detected() {
        for input in [
            // rustfmt 的多行调用：`&` 实参另起一行
            "let n = write_all(\n    &buf,\n    &mut file,\n);\n",
            // rustfmt 的多行闭包实参：`|` 另起一行
            "let v = items.iter().map(\n    |x| x * 2,\n).collect::<Vec<_>>();\n",
            // C / JS 的取反括号表达式（`==` 不是 LDAP 的运算符）
            "if (!(a == b)) { return EINVAL; }\n",
            "if (!(a != b) && !(c)) { abort(); }\n",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
        }
    }

    /// 收紧的另一半：三个运算符家族的过滤器形态必须照报。
    #[test]
    fn operator_filters_still_detected_after_tightening() {
        for input in [
            "(&(uid=admin)(!(|(cn=*))))",
            "(|(cn=admin))",
            "(!(uid=*))",
            "(!(cn~=adm))",
        ] {
            assert_hit(input);
        }
    }
}
