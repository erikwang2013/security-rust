// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：序列化载荷本身（`O:8:"` / `a:1:{`）与魔术方法的**调用形态**。
/// 各分支合成一条 alternation：原来 N 条正则在干净输入上要各扫一遍，合成后一次扫完。
/// 分支的 flags 收在 `(?i:…)` 里——裸 `(?i)` 会顺延到后面的分支，
/// 让 `O:\d+:"` 也变成大小写不敏感（`o:8:` 本不该命中）。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            r#"O:\d+:"#,
            r#"|C:\d+:"#,
            r"|(?i:unserialize\s*\()",
            // PHP 魔术方法必须是调用形态：后面跟 `(`。裸名字在文档里满地都是
            // （本库 README 的检测器表格就写着 `__wakeup`/`__destruct`/`__toString`），
            // 那是「在讨论它们」，不是攻击。`function __construct()` 照报。
            r"|(?i:__wakeup\s*\()",
            r"|(?i:__destruct\s*\()",
            r"|(?i:__construct\s*\()",
            r"|(?i:__toString\s*\()",
            // `__get`/`__set`/`__call` 同样：裸名字会误杀 Python 的 `__getitem__` /
            // `__set_name__` / `__getattr__`（`\b` 挡不住，`_` 是词字符）。
            r"|(?i:__(?:get|set|call)\s*\()",
            r"|a:\d+:\{",
        ]
        .concat(),
    )
    .unwrap()
});

/// 弱信号：裸魔术方法名。它确实是反序列化 gadget 的标识，但单看只是一个词——
/// 报 Low，单条不足以拒绝。四条分支的 flags 完全一致，提到最前面即可。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)__wakeup|__destruct|__construct|__toString").unwrap()
});

pub struct DeserializationDetector;

impl Detector for DeserializationDetector {
    fn name(&self) -> &'static str {
        "deserialization"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Data,
            Severity::Critical,
            "PHP deserialization attack detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Data,
                Severity::Low,
                "PHP magic method name present (weak signal)",
                input,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(DeserializationDetector.name(), "deserialization");
    }

    #[test]
    fn detects_serialized_php_object() {
        let input = r#"O:8:"stdClass":1:{s:4:"test";s:5:"value";}"#;
        let r = DeserializationDetector
            .detect(input)
            .expect("serialized PHP object should be detected");
        assert_eq!(r.attack_type, "deserialization");
        assert_eq!(r.category, AttackCategory::Data);
        assert_eq!(r.severity, Severity::Critical);
        assert_eq!(r.offset, 0);
    }

    #[test]
    fn detects_serialized_arrays_and_magic_methods() {
        for payload in [
            r#"a:1:{s:4:"key";s:5:"value";}"#,
            r#"C:5:"Foo":0:{}"#,
            "unserialize($_POST['data'])",
            "trigger __wakeup magic method",
            "call __destruct on shutdown",
            "override __toString()",
        ] {
            let r = DeserializationDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert!(
                !r.matched_pattern.is_empty(),
                "matched_pattern empty for {:?}",
                payload
            );
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_php_magic_method_calls_only() {
        for payload in [
            "function __get($name) { return $this->data[$name]; }",
            "$obj->__call('method', $args)",
            "$this->__set('key', $value)",
            "public function __get ($name)",
        ] {
            assert!(
                DeserializationDetector.detect(payload).is_some(),
                "expected detection for {:?}",
                payload
            );
        }
    }

    /// 魔术方法名分档：调用形态（`function __construct()`）是 PHP 源码，Critical；
    /// 裸名字只是词——文档表格里满是这样写的（本库 README 就是），Low。
    #[test]
    fn magic_method_call_is_critical_bare_name_is_low() {
        for payload in [
            "function __construct($config) { $this->config = $config; }",
            "public function __destruct() { $this->close(); }",
            "override __toString()",
            "function __wakeup() { $this->init(); }",
        ] {
            let r = DeserializationDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.severity, Severity::Critical, "payload {:?}", payload);
        }
        for input in [
            "| **deserialization** | `__wakeup`/`__destruct`/`__toString` 等魔术方法 | Critical |",
            "trigger __wakeup magic method",
            "call __destruct on shutdown",
        ] {
            let r = DeserializationDetector
                .detect(input)
                .unwrap_or_else(|| panic!("expected weak detection for {:?}", input));
            assert_eq!(r.severity, Severity::Low, "input {:?}", input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "Order: 8 items please",
            "O:8",
            "unserialize_data is not a call",
            "constructor and destructor in C++",
            "a:b:{not a serialized array}",
        ] {
            assert!(
                DeserializationDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    /// 真实语料：Python 的 dunder 与 `__get`/`__set`/`__call` 同前缀，`\b` 挡不住（`_` 是
    /// 词字符），裸名字版本会把任何 Python 文件判成 Critical 反序列化攻击。
    #[test]
    fn ignores_realistic_python_source() {
        for input in [
            "def __getitem__(self, key): return self.data[key]",
            "def __getattr__(self, n)",
            "def __getattr__(self, name):\n    raise AttributeError(name)\n",
            "def __setattr__(self, name, value):\n    self.__dict__[name] = value\n",
            "__set_name__ is called by the descriptor protocol.",
            "class Config:\n    def __init__(self):\n        self.__get = 1\n",
            "Python docs mention __getattribute__, __set_name__ and __call__ in prose.",
        ] {
            assert!(
                DeserializationDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(DeserializationDetector.detect("").is_none());
        assert!(DeserializationDetector.detect("   ").is_none());
        assert!(
            DeserializationDetector
                .detect("日本語のテキストです")
                .is_none()
        );
    }
}
