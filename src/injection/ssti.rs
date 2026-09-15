// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

// `${...}` / `{{...}}` 本身**不是**信号：shell、Spring `@Value("${x}")`、
// `@Value` 占位符、JS 模板串、Thymeleaf、Vue/Handlebars 变量全是这个语法，
// 拿定界符当特征等于把正常业务流量全拦下。SSTI 的真实信号是**表达式被求值**：
//   1. 定界符里出现字面量之间的算术 —— `{{7*7}}`、`${7*7}`，最经典的求值探针；
//   2. 表达式开头的对象/运行时访问 —— `{{config}}`、`${T(java.lang.Runtime)}`；
//   3. Python 魔术属性 —— 没有正常业务用法。
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // 求值探针：数字 + 运算符 + 数字。要求定界符成对闭合（`{{7*7` 不报）。
        // 间隙用 `[^{}]` 而不是 `.`，避免跨多个定界符乱吞。
        Regex::new(r"\{\{[^{}]{0,120}?\d+[ \t]*[-+*/%][ \t]*\d+[^{}]{0,120}?\}\}").unwrap(),
        Regex::new(r"\$\{[^{}]{0,120}?\d+[ \t]*[-+*/%][ \t]*\d+[^{}]{0,120}?\}").unwrap(),
        // `config` 只在 `{{...}}` 里算信号（Jinja/Flask 的内置对象）；
        // `${config}` 是 shell/SpEL 的普通属性占位符，不算。
        // 必须紧跟在定界符之后：`{{ app_config }}` 是普通变量名。
        Regex::new(r"\{\{[ \t]*config\b").unwrap(),
        // SpEL 的类型访问 `T(...)` 与静态成员访问 `@Type@method`。
        Regex::new(r"\$\{[ \t]*(?:T[ \t]*\(|@[\w.]+@)").unwrap(),
        // 以下形状本身即信号，不依赖里面写了什么
        Regex::new(r"\{%\s*.*?\s*%\}").unwrap(),
        Regex::new(r"<%=").unwrap(),
        Regex::new(r"<%@").unwrap(),
        Regex::new(r"#set\s*\(").unwrap(),
        Regex::new(r"__mro__").unwrap(),
        Regex::new(r"__subclasses__").unwrap(),
        Regex::new(r"__globals__").unwrap(),
        Regex::new(r"__builtins__").unwrap(),
        Regex::new(r"__class__").unwrap(),
        Regex::new(r"__dict__").unwrap(),
    ]
});

pub struct SstiDetector;

impl Detector for SstiDetector {
    fn name(&self) -> &'static str {
        "ssti"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            &PATTERNS,
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "Server-Side Template Injection detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SstiDetector {
        SstiDetector
    }

    fn assert_hit(input: &str) {
        crate::test_helpers::assert_detected(
            &det(),
            input,
            AttackCategory::Injection,
            Severity::Critical,
        );
    }

    #[test]
    fn name_is_ssti() {
        assert_eq!(det().name(), "ssti");
    }

    #[test]
    fn detects_common_payloads() {
        for input in [
            "{{7*7}}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "${7*7}",
            "{% include '/etc/passwd' %}",
            "<%= params[:x] %>",
            r#"<%@ page import="java.util.*" %>"#,
            "#set($x = 5)",
            "{{config.__init__.__globals__}}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn benign_inputs_not_detected() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "The total is $5.00 plus tax",
            "Please enter your name below",
            "The class of 2026 graduates in May",
            "100% of users agree with this",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    /// 变量插值到处都是，定界符本身不是信号
    #[test]
    fn plain_interpolation_not_detected() {
        for input in [
            "the price is ${amount}",
            "${user}${pass}",
            "@Value(\"${x.y.z}\")",
            "${env:JAVA_HOME}",
            "const x = `${name}`",
            "${#strings.toUpperCase(name)}",
            "{{ name }}",
            "{{ app_config }}",
            "${timeout:30s}",
            "${PATH:-/usr/bin}",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
        }
    }

    /// 求值探针与运行时访问才是信号
    #[test]
    fn evaluation_probes_and_runtime_access_detected() {
        for input in [
            "${7*7}",
            "{{7*7}}",
            "{{ 7 * 7 }}",
            "${{7*7}}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{ config.items }}",
            "${T(java.lang.Runtime)}",
            "${@java.lang.Runtime@getRuntime()}",
            "{{ ''.__class__.__mro__ }}",
            "{{ self.__dict__ }}",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn edge_cases() {
        assert!(det().detect("").is_none());
        assert!(det().detect(" \t\n ").is_none());
        assert!(det().detect("你好世界 こんにちは").is_none());
        // near misses: delimiters incomplete, or magic names uppercase (case-sensitive)
        assert!(det().detect("{7*7}").is_none());
        assert!(det().detect("{{7*7").is_none());
        assert!(det().detect("__CLASS__").is_none());
        assert!(det().detect("{$x=7}").is_none());
    }

    #[test]
    fn obfuscated_variants_detected() {
        for input in [
            "{{ ''.__class__.__MRO__[1] }}",
            "{{ self.__dict__ }}",
            "{{request.application.__globals__}}",
        ] {
            assert_hit(input);
        }
    }
}
