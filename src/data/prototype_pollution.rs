// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：污染必须带**写入**形态。`__proto__` 作为键（`"__proto__":`、
/// `[__proto__]`）或被赋值（`__proto__ = x`）才是污染；裸 token 不是。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    // 九条分支的 flags 完全一致（都是 `(?i)`），提到最前面即可。
    Regex::new(
        &[
            // 键形态：JSON/YAML 的 `"__proto__":`、方括号的 `[__proto__]` / `o[__proto__][x]`
            r#"(?i)__proto__(?:["'\[\]])"#,
            // 赋值形态。`=` 后跟 `[ \t]*[^=\s]` 排除 `===` / `==` 比较——
            // `obj.__proto__ === Array.prototype` 是读取原型，不是污染；
            // 而 `obj.__proto__ = {}` / `?__proto__=1` 是写入。
            r"|__proto__\s*=[ \t]*[^=\s]",
            r"|constructor\[",
            r"|constructor\.prototype",
            r"|__defineGetter__",
            r"|__defineSetter__",
            r"|__lookupGetter__",
            r"|__lookupSetter__",
            r"|hasOwnProperty\[",
        ]
        .concat(),
    )
    .unwrap()
});

/// 弱信号：裸 `__proto__`。任何碰原型链的 JS 都会出现它——`const p = obj.__proto__;`
/// 是语言本身的读法——但它也确实是污染的载体（`obj.__proto__.x = 1` 这条路径
/// 上面的强形态没覆盖）。报 Low：单条不足以拒绝。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)__proto__").unwrap());

pub struct PrototypePollutionDetector;

impl Detector for PrototypePollutionDetector {
    fn name(&self) -> &'static str {
        "prototype_pollution"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Data,
            Severity::High,
            "JavaScript prototype pollution detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Data,
                Severity::Low,
                "__proto__ referenced (weak signal)",
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
        assert_eq!(PrototypePollutionDetector.name(), "prototype_pollution");
    }

    #[test]
    fn detects_proto_and_constructor_payloads() {
        for payload in [
            r#"{"__proto__": {"isAdmin": true}}"#,
            r#"{"__proto__": {"polluted": true}}"#,
            "obj.constructor.prototype.isAdmin = true",
            "a[constructor[0]]",
            "o[__proto__][isAdmin]",
        ] {
            let r = PrototypePollutionDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "prototype_pollution");
            assert_eq!(r.category, AttackCategory::Data);
            assert_eq!(r.severity, Severity::High);
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
    fn detects_legacy_getter_setter_apis() {
        for payload in [
            "__defineGetter__('x', fn)",
            "__defineSetter__('x', fn)",
            "__lookupGetter__('x')",
            "__lookupSetter__('x')",
            "hasOwnProperty['isAdmin']",
        ] {
            let r = PrototypePollutionDetector
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

    /// 裸 `__proto__` 是语言本身的读法，不是污染；只有键/赋值形态才写成 High。
    /// 攻击方向必须仍然 High：降档不能靠「把检测删掉」达成。
    #[test]
    fn bare_proto_reference_is_low_key_shape_is_high() {
        for payload in [
            r#"{"__proto__": {"isAdmin": true}}"#,
            r#"{"__proto__":{"polluted":1}}"#,
            "o[__proto__][isAdmin]",
            "obj.__proto__ = {}",
            "?__proto__[x]=1",
        ] {
            let r = PrototypePollutionDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.severity, Severity::High, "payload {:?}", payload);
        }
        // 读原型 + 文档里的裸 token：仍检出（弱信号是信号），但只有 Low
        for input in [
            "const p = obj.__proto__;",
            "if (obj.__proto__ === Array.prototype) { init(); }",
            "| **prototype_pollution** | `__proto__` 原型链污染 | High |",
        ] {
            let r = PrototypePollutionDetector
                .detect(input)
                .unwrap_or_else(|| panic!("expected weak detection for {:?}", input));
            assert_eq!(r.severity, Severity::Low, "input {:?}", input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "constructor",
            "hasOwnProperty",
            "proto",
            "the prototype chain is a concept",
        ] {
            assert!(
                PrototypePollutionDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(PrototypePollutionDetector.detect("").is_none());
        assert!(PrototypePollutionDetector.detect("   ").is_none());
        assert!(PrototypePollutionDetector.detect("＿＿proto＿＿").is_none()); // fullwidth underscores
        assert!(PrototypePollutionDetector.detect("Прототип").is_none());
    }
}
