// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

/// webshell 特征：**文件本身就是检出项**，不是一个碰巧出现的 token。`<?php`/`<%@` 的
/// 唯一读法就是「这是可被服务端执行的代码」——与 `data_leak` 的 PAN 同类，出现即泄露。
///
/// 故这一档不设强弱分层：JSP 页面与 JSP webshell 的前导字节逐字节相同
/// （`<%@ page language="java" … %>` 与 `<%@ page import="java.io.*" %>` 同一形态），
/// 把 `<%@`/`<%=` 降档等于让 webshell 落到拒绝线以下 —— 那是换个方式删检测。
/// 代价是扫描**正在对外提供的**页面（而不是上传的文件）也会命中；那属于输入域不符，
/// 消息文案 `Malicious file upload detected` 已点明域。
/// 十五条分支合成一条 alternation。flags **完全一致**（都是 `(?i)`），
/// 提到最前面即可，无需逐条包裹。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            r"(?i)<\?php",
            r"|<\?=",
            r"|<%\s*@",
            r"|<%\s*=",
            r#"|<script\s+language\s*=\s*["']?(?:php|vbscript|jscript)["']?"#,
            r"|eval\s*\(\s*\$",
            r"|system\s*\(\s*\$",
            r"|exec\s*\(\s*\$",
            r"|passthru\s*\(\s*\$",
            r"|shell_exec\s*\(\s*\$",
            r"|\$_GET\[",
            r"|\$_POST\[",
            r"|\$_REQUEST\[",
            r"|\$_SERVER\[",
            r"|base64_decode\s*\(",
        ]
        .concat(),
    )
    .unwrap()
});

pub struct UploadDetector;

impl Detector for UploadDetector {
    fn name(&self) -> &'static str {
        "upload"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::File,
            Severity::Critical,
            "Malicious file upload detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(UploadDetector.name(), "upload");
    }

    #[test]
    fn detects_php_tags() {
        for payload in [
            "<?php system($_GET['cmd']); ?>",
            "<?= shell_exec($_POST['cmd']) ?>",
            "<?php echo 'hello';",
        ] {
            let r = UploadDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "upload");
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
    fn detects_asp_and_script_language_tags() {
        for payload in [
            "<% @ Page Language=\"C#\" %>",
            "<% = response.write(1) %>",
            "<script language='vbscript'>MsgBox 1</script>",
            "<script language=\"jscript\">x()</script>",
            "<script language=php>echo 1;</script>",
        ] {
            let r = UploadDetector
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
    fn detects_exec_functions_and_superglobals() {
        for payload in [
            "eval($code);",
            "system($cmd);",
            "exec($cmd);",
            "passthru($cmd);",
            "shell_exec($cmd);",
            "$_GET['cmd']",
            "$_POST['cmd']",
            "$_REQUEST['cmd']",
            "$_SERVER['REQUEST_URI']",
            "base64_decode('aGVsbG8=')",
        ] {
            let r = UploadDetector
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
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "php is a popular language",
            "<script>alert(1)</script>",
            "system('id')",
            "exec('ls')",
            "base64_decode",
            "$_GET",
            "eval()",
        ] {
            assert!(
                UploadDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(UploadDetector.detect("").is_none());
        assert!(UploadDetector.detect("   ").is_none());
        assert!(UploadDetector.detect("＜？php echo 1;").is_none()); // fullwidth angle bracket
        assert!(UploadDetector.detect("<? phpx echo 1;").is_none()); // space breaks the tag
    }
}
