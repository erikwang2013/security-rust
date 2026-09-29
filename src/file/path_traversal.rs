// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

/// 强信号：**多级**跨越。单级 `../` 在源码与文档里是相对路径
/// （`include_str!("../docs/pet.svg")`、`from '../lib'`、`[guide](../docs/x.md)`），
/// 两级以上才是「跳出目录树」的攻击形态。百分号编码形态留在强档：正常内容
/// 不会把点号编码成 `%2e`，出现即有人刻意构造。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    // 十四条分支合成一条 alternation。flags **不一致**（`(?:\.\./){2,}` 等四条大小写中性，
    // 其余十条是 `(?i)`），故逐条包在 `(?i:…)` 里，不让 `(?i)` 顺延。
    Regex::new(
        &[
            r"(?:\.\./){2,}",
            r"|(?:\.\.\\){2,}",
            r"|(?i:\.\.%2[Ff])",
            // 反斜杠的百分号编码：`..%5c..%5cwindows%5csystem32`，`..%2f` 早有覆盖，这条漏了
            r"|(?i:\.\.%5[Cc])",
            r"|(?i:%2[Ee]%2[Ee])",
            r"|(?i:php://filter)",
            r"|(?i:php://input)",
            r"|(?i:data://)",
            r"|(?i:expect://)",
            r"|(?i:phar://)",
            r"|(?i:zip://)",
            r"|(?i:glob://)",
            r"|%00",
            r"|\x00",
        ]
        .concat(),
    )
    .unwrap()
});

/// 弱信号：单级 `../` / `..\`——它既是一次穿透目录的 LFI 载荷，也是每一份源码里
/// 的相对路径，两者字节相同（`?file=../wp-config.php` 与 `include_str!("../x")`），
/// 无法用正则区分。报 Low：单条不足以拒绝，聚合分交给调用方。
static WEAK_PATTERNS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\./|\.\.\\").unwrap());

pub struct PathTraversalDetector;

impl Detector for PathTraversalDetector {
    fn name(&self) -> &'static str {
        "path_traversal"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::File,
            Severity::Critical,
            "Path traversal attack detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::File,
                Severity::Low,
                "Single-level parent directory reference (weak signal)",
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
        assert_eq!(PathTraversalDetector.name(), "path_traversal");
    }

    #[test]
    fn detects_dotdot_traversal() {
        for payload in [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "a/../../b",
        ] {
            let r = PathTraversalDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "path_traversal");
            assert_eq!(r.category, AttackCategory::File);
            assert_eq!(r.severity, Severity::Critical);
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
    fn detects_encoded_traversal() {
        for payload in [
            "..%2f..%2fetc/passwd",
            "..%2Fetc/passwd",
            "%2e%2e%2fetc/passwd",
            "%2E%2E/win.ini",
            "..%5c..%5cwindows%5csystem32",
            "..%5C..%5Cwindows%5Csystem32",
        ] {
            let r = PathTraversalDetector
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
    fn detects_wrappers_and_null_bytes() {
        for payload in [
            "php://filter/convert.base64-encode/resource=config.php",
            "php://input",
            "data://text/plain;base64,PD9waHA=",
            "expect://id",
            "phar://archive.phar",
            "zip://archive.zip#a",
            "glob://*.php",
            "file%00.php",
        ] {
            let r = PathTraversalDetector
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

    /// 多级跨越仍然是 Critical——这是攻击形态；单级只有 Low。
    #[test]
    fn multi_level_is_critical_single_level_is_low() {
        for payload in [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "a/../../b",
            "..\\..\\windows\\system32",
        ] {
            let r = PathTraversalDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.severity, Severity::Critical, "payload {:?}", payload);
        }
        // 单级：既是 LFI 载荷也是相对路径，字节相同 → Low
        for input in [
            "../etc/passwd",
            "include_str!(\"../docs/pet.svg\")",
            "import { render } from '../lib/render.js'",
            "[guide](../docs/api.md)",
            r"C:\Users\erik\..\backup\report.docx",
        ] {
            let r = PathTraversalDetector
                .detect(input)
                .unwrap_or_else(|| panic!("expected weak detection for {:?}", input));
            assert_eq!(r.severity, Severity::Low, "input {:?}", input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "etc/passwd",
            "a.b/c",
            "..",
            "...",
            "php:",
            "zip:archive.zip",
            "/etc/passwd",
            // 真实语料：路径、URL、百分号编码本身都不算穿越
            r"C:\Users\erik\Documents\report.docx",
            "https://example.com/docs/api/guide",
            "path%5Csegment%5Cname",
            "The file is .. hidden and ... is an ellipsis; see docs/readme.md (relative link).",
        ] {
            assert!(
                PathTraversalDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(PathTraversalDetector.detect("").is_none());
        assert!(PathTraversalDetector.detect("   ").is_none());
        assert!(PathTraversalDetector.detect("…/…/秘密のファイル").is_none()); // unicode ellipsis
    }
}
