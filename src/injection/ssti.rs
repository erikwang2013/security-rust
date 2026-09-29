// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

// `${...}` / `{{...}}` 本身**不是**信号：shell、Spring `@Value("${x}")`、
// `@Value` 占位符、JS 模板串、Thymeleaf、Vue/Handlebars 变量全是这个语法，
// 拿定界符当特征等于把正常业务流量全拦下。SSTI 的真实信号是**表达式被求值**：
//   1. 定界符里出现字面量之间的算术 —— `{{7*7}}`、`${7*7}`、`<%= 7*7 %>`；
//      已知上限，**不要「修」**：操作数两侧都是字面量数字时，形状与模板源码里
//      `{{ 10 % 2 }}` 完全相同，所以它报 Critical。要求操作数是标识符会同时放过
//      `{{7*7}}`，而后者正是 SSTI 的规范判据；且模板文件与请求体是不同的输入域。
//      `{{ count % 2 }}`、`{{ n % 10 }}`、`{{ a % b }}` 都 clean（标识符操作数）。
//   2. 表达式开头的对象/运行时访问 —— `{{config}}`、`${T(java.lang.Runtime)}`；
//   3. Python 魔术属性**在定界符内** —— 裸的 `__class__`/`__dict__` 是普通 Python
//      （`self.__class__.__name__`、`obj.__dict__`、`Plugin.__subclasses__()`）。
// 模板指令本身（`{% %}`、`<%=`、`#set(`）在模板源码里就是功能，形状与攻击完全相同，
// 单独出现不足以拒绝，放 WEAK_PATTERNS。
/// 8 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 8 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // 求值探针：数字 + 运算符 + 数字。要求定界符成对闭合（`{{7*7` 不报）。
        // 间隙用 `[^{}]` 而不是 `.`，避免跨多个定界符乱吞。
        // 右操作数允许带引号：Twig/Jinja 的 `{{7*'7'}}`（字符串重复求值）与不加引号
        // 的 `{{7*7}}` 是同一个探针，引号只是骗过按数字匹配的 WAF。
        r#"\{\{[^{}]{0,120}?\d+[ \t]*[-+*/%][ \t]*['"]?\d+[^{}]{0,120}?\}\}"#,
        r#"|\$\{[^{}]{0,120}?\d+[ \t]*[-+*/%][ \t]*['"]?\d+[^{}]{0,120}?\}"#,
        // ERB/ASP 同理：裸 `<%=` 是模板源码的常规写法（见 WEAK），带算术求值的才是探针
        r#"|<%=[^{}]{0,120}?\d+[ \t]*[-+*/%][ \t]*['"]?\d+[^{}]{0,120}?%>"#,
        // `config` 只在 `{{...}}` 里算信号（Jinja/Flask 的内置对象）；
        // `${config}` 是 shell/SpEL 的普通属性占位符，不算。
        // 必须紧跟在定界符之后：`{{ app_config }}` 是普通变量名。
        r"|\{\{[ \t]*config\b",
        // SpEL 的类型访问 `T(...)` 与静态成员访问 `@Type@method`。
        r"|\$\{[ \t]*(?:T[ \t]*\(|@[\w.]+@)",
        // Jinja/Twig 的 include/extends 只有带绝对路径或 `..` 才是 LFI：
        // `{% include 'header.html' %}` 是模板的正常写法。
        r#"|\{%\s*(?:include|extends|import|from)\s+['"]\s*(?:/|\.\.)"#,
        // 魔术属性只有在**定界符内**才是逃逸链 —— 裸的 `__class__` 是普通 Python
        // （`self.__class__.__name__`、`dict(obj.__dict__)`、`Plugin.__subclasses__()`）。
        // 间隙用 `[^{}%]` 避免跨定界符乱吞。
        r"|\{\{[^{}%]{0,160}?__(?:class|dict|mro|subclasses|globals|builtins)__|\{%[^{}%]{0,160}?__(?:class|dict|mro|subclasses|globals|builtins)__|\$\{[^{}%]{0,160}?__(?:class|dict|mro|subclasses|globals|builtins)__",
        // FreeMarker 的反射内建。`?new(` 是 FreeMarker 的 builtin
        // （`"freemarker.template.utility.Execute"?new()`），别处没有这个写法。
        r"|(?i:\?new\s*\()",
    ))
    .unwrap()
});

/// 弱信号：模板指令「出现」本身就是模板语言的功能 —— `{% if %}`、`<%= %>`、`#set(`、
/// `<#assign>` 在正常模板源码里满地都是，与攻击形状完全相同；裸魔术属性则是普通
/// Python 代码。都保留检出，但单条不拒绝。
/// 6 条分支合并成 1 条 alternation —— `regex_detect` 对列表里每条 `Regex` 各跑一次
/// `find`，干净输入下 6 次全文扫描变 1 次。分支顺序 = 原 vec 顺序（同一位置上取最左
/// 分支；与「按列表顺序取第一条命中的模式」相比偏移量可能不同，档位不变）。
/// 内联 flag 一律裹进 `(?i:…)` —— 裸 `(?i)` 的作用域会蔓延到它后面拼进来的分支。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\{%\s*.*?\s*%\}",
        r"|<%=",
        r"|<%@",
        r"|#set\s*\(",
        // `<` 必须紧贴在 `#` 前：`href="#assign x"` 这类锚点里 `#` 前面是引号，不命中
        r"|(?i:<#assign\s)",
        r"|__(?:class|dict|mro|subclasses|globals|builtins)__",
    ))
    .unwrap()
});

pub struct SstiDetector;

impl Detector for SstiDetector {
    fn name(&self) -> &'static str {
        "ssti"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Injection,
            Severity::Critical,
            "Server-Side Template Injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Injection,
                Severity::Low,
                "Template directive / magic attribute present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> SstiDetector {
        SstiDetector
    }

    fn assert_hit(input: &str) {
        assert_hit_at(input, Severity::Critical);
    }

    fn assert_hit_at(input: &str, severity: Severity) {
        crate::test_helpers::assert_detected(&det(), input, AttackCategory::Injection, severity);
    }

    #[test]
    fn name_is_ssti() {
        assert_eq!(det().name(), "ssti");
    }

    #[test]
    fn detects_common_payloads() {
        for (input, severity) in [
            // 强信号：求值探针 / 定界符内的逃逸链，Critical
            ("{{7*7}}", Severity::Critical),
            ("{{ ''.__class__.__mro__[1].__subclasses__() }}", Severity::Critical),
            ("${7*7}", Severity::Critical),
            ("{% include '/etc/passwd' %}", Severity::Critical),
            ("{{config.__init__.__globals__}}", Severity::Critical),
            // 弱信号：模板指令出现本身，Low
            ("<%= params[:x] %>", Severity::Low),
            (r#"<%@ page import="java.util.*" %>"#, Severity::Low),
            ("#set($x = 5)", Severity::Low),
        ] {
            assert_hit_at(input, severity);
        }
    }

    /// 正常模板源码。`{% if %}`、`<%= @user.name %>`、`#set(`、`<#assign>` 是各自模板
    /// 语言的功能写法，每个模板文件都长这样；它们曾按 Critical 被判 SSTI，整份文件被拒。
    #[test]
    fn template_source_is_low_not_critical() {
        for input in [
            "{% if user.is_admin %}\n  <p>Admin</p>\n{% endif %}",
            "{% for item in items %}\n  <li>{{ item.name }}</li>\n{% endfor %}",
            "<h1>Hello <%= @user.name %></h1>",
            r#"<%@ page language="java" contentType="text/html; charset=UTF-8" %>"#,
            "#set($x = 5)",
            "<#assign title=\"Home\">",
        ] {
            assert_hit_at(input, Severity::Low);
        }
    }

    /// 裸魔术属性是普通 Python：`self.__class__.__name__` / `obj.__dict__` /
    /// 插件注册表的 `Plugin.__subclasses__()`。定界符内的同名字段仍是 Critical。
    #[test]
    fn bare_python_dunders_are_low_but_delimited_ones_stay_critical() {
        for input in [
            "return f\"<Store {self.__class__.__name__}>\"",
            "return dict(self.__dict__)",
            "return [c for c in Plugin.__subclasses__()]",
        ] {
            assert_hit_at(input, Severity::Low);
        }
        for input in [
            "{{ self.__dict__ }}",
            "{{ ''.__class__.__mro__ }}",
            "${config.__class__}",
        ] {
            assert_hit(input);
        }
    }

    /// 正常 Python 里 `__getitem__` / `__set_name__` 这类协议方法不是逃逸链 ——
    /// 白名单只含 6 个逃逸用的魔术属性名，别的一个都不碰。
    #[test]
    fn python_protocol_methods_not_detected() {
        for input in [
            "def __getitem__(self, key):\n    return self._data[key]",
            "__set_name__ is called by the descriptor protocol.",
            "def __getattr__(self, name):\n    raise AttributeError(name)",
        ] {
            crate::test_helpers::assert_clean(&det(), input);
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
            // 字面量数字两侧 —— 与模板源码同形的已知上限，钉住它以免被「修掉」
            "{{ 10 % 2 }}",
            "total = {{ 10 % 2 }}",
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

    /// 带引号的操作数与 FreeMarker 指令
    #[test]
    fn freemarker_and_quoted_operand_detected() {
        for input in [
            "{{7*'7'}}",
            r#"{{7*"7"}}"#,
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            r#"${"freemarker.template.utility.Execute"?new()("id")}"#,
        ] {
            assert_hit(input);
        }
    }

    /// 反向对照：`#assign` 的那个 `#` 在 HTML/URL 里满地都是，`?new` 也一样
    #[test]
    fn assign_and_new_lookalikes_not_detected() {
        for input in [
            r##"<a href="#assign something">x</a>"##,
            r##"<a href="#assign">x</a>"##,
            "https://example.com/#assign-section",
            "q?new=1",             // `?new` 后面不是 (
            "{{ '7' }}",           // 带引号的数字，但没有运算
            r#"{{ "hello" * 3 }}"#, // 运算符两侧没有数字对
            // 求值探针的边界：两侧都是**字面量数字**才报，标识符操作数不报。
            // `{{ 10 % 2 }}` 报 Critical 是已知上限（见文件头注释），不是待修的 bug。
            "{{ count % 2 }}",
            "{{ n % 10 }}",
            "{{ a % b }}",
            "The template renders the remainder of {{ a % b }} on the page.",
        ] {
            assert!(det().detect(input).is_none(), "false positive: {input}");
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

