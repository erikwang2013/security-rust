// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

static CC_PAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap()
});

/// 泄露形态：**凭据出现在不该出现的地方**。`AKIA`/PEM/`sk-` 本身就是秘密，出现即
/// 泄露；连接串不是 —— 秘密是 URL 里的 userinfo，不是 scheme 本身。`redis://shared-memory`、
/// `postgres://localhost:5432/app` 这种没有 `@` 的地址是配置项的常态（本仓库
/// README 的检测器表就写着 `mongodb://`/`mysql://`/`postgresql://`/`redis://`），
/// 收紧前它们全是 Critical。故连接串一律要求 `@`：`user:pass@`（`mysql://root:secret@db`）
/// 与只有 user 的 `mongodb+srv://admin@cluster` 都算 —— 后者是既有的正例，界就划在这里。
/// 十二条分支合成一条 alternation。前六条（密钥 / 证书前缀）大小写中性、必须
/// 保持中性，后六条是 `(?i)`；flags 不一致，故逐条包裹。
/// 顺序照旧：`-----BEGIN\s*(?:RSA\s*)?PRIVATE\s*KEY` 排在 `DSA`/`EC`/`PGP` 之前，
/// 合并后同一位置仍按原次序取分支（alternation 是 leftmost-first），行为不变。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &[
            r"AKIA[0-9A-Z]{16}",
            r"|-----BEGIN\s*(?:RSA\s*)?PRIVATE\s*KEY",
            r"|-----BEGIN\s*CERTIFICATE",
            r"|-----BEGIN\s*DSA\s*PRIVATE",
            r"|-----BEGIN\s*EC\s*PRIVATE",
            r"|-----BEGIN\s*PGP\s*PRIVATE",
            r"|sk-[A-Za-z0-9]{32,}",
            r"|(?i:mongodb(?:\+srv)?://[^/\s@]+@[^/\s]+)",
            r"|(?i:mysql://[^/\s@]+@[^/\s]+)",
            r"|(?i:postgres(?:ql)?://[^/\s@]+@[^/\s]+)",
            r"|(?i:redis://[^/\s@]+@[^/\s]+)",
            r"|(?i:jdbc:[a-z]+://)",
        ]
        .concat(),
    )
    .unwrap()
});

fn luhn_valid(pan: &str) -> bool {
    let mut len = 0;
    let mut sum = 0u32;
    for (i, b) in pan.bytes().rev().filter(|b| b.is_ascii_digit()).enumerate() {
        len += 1;
        let d = (b - b'0') as u32;
        if i % 2 == 1 {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
    }
    len >= 13 && sum.is_multiple_of(10)
}

pub struct DataLeakDetector;

impl Detector for DataLeakDetector {
    fn name(&self) -> &'static str {
        "data_leak"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        if let Some(m) = CC_PAN.find(input)
            && luhn_valid(m.as_str())
        {
            return Some(DetectionResult {
                attack_type: self.name().into(),
                category: AttackCategory::File,
                severity: Severity::Critical,
                matched_pattern: m.as_str().to_string(),
                offset: m.start(),
                message: "Sensitive data leak detected (credit card)".into(),
            });
        }
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::File,
            Severity::Critical,
            "Sensitive data leak detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::assert_clean;

    #[test]
    fn name_returns_attack_type() {
        assert_eq!(DataLeakDetector.name(), "data_leak");
    }

    #[test]
    fn detects_valid_credit_cards() {
        for payload in ["4111111111111111", "4242424242424242", "5555555555554444"] {
            let r = DataLeakDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "data_leak");
            assert_eq!(r.category, AttackCategory::File);
            assert_eq!(r.severity, Severity::Critical);
            assert_eq!(r.matched_pattern, payload);
            assert!(
                r.offset <= payload.len(),
                "offset out of range for {:?}",
                payload
            );
        }
    }

    #[test]
    fn detects_cloud_and_api_keys() {
        for payload in [
            "AKIAIOSFODNN7EXAMPLE",
            "AWS_ACCESS_KEY=AKIA1234567890ABCDEF",
            "sk-abcdefghijklmnopqrstuvwxyz123456",
            "key=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
        ] {
            let r = DataLeakDetector
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
    fn detects_private_keys_and_certificates() {
        for payload in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN CERTIFICATE-----",
        ] {
            let r = DataLeakDetector
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
    fn detects_database_connection_strings() {
        for payload in [
            "mongodb://admin:password@localhost:27017/db",
            "mongodb+srv://admin@cluster.example.com/db",
            "mysql://root:secret@db:3306/app",
            "postgresql://user:pass@pg:5432/db",
            "postgres://user:pass@pg:5432/db",
            "redis://:secret@cache:6379/0",
            "jdbc:mysql://localhost:3306/app",
        ] {
            let r = DataLeakDetector
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

    /// 带 userinfo 的连接串仍是 Critical：`user:pass@` 与只有 user 的 `user@` 都算，
    /// 界划在「URL 里有没有 userinfo」，不是划在「有没有密码」。
    #[test]
    fn credentialed_connection_strings_are_still_critical() {
        for payload in [
            "mongodb://admin:password@localhost:27017/db",
            "mongodb+srv://admin@cluster.example.com/db",
            "postgres://app:pw@10.0.0.5:5432/db",
            "redis://:secret@cache:6379/0",
        ] {
            let r = DataLeakDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.severity, Severity::Critical);
        }
    }

    /// 不带 userinfo 的连接 URL **不是**泄露 —— 它只是指向一条服务的地址，配置里
    /// 到处都有。收紧前这些全部命中 Critical，本仓库 README 的检测器表因此被自己的
    /// data_leak 判成 Critical。
    #[test]
    fn connection_urls_without_credentials_are_clean() {
        for input in [
            "redis://shared-memory",
            "memory: redis://shared-memory",
            "postgres://localhost:5432/app",
            "mysql://db.internal:3306",
            "MONGODB_URI=mongodb://localhost",
            "| **data_leak** | 数据库连接串 `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:` | Critical |",
        ] {
            assert_clean(&DataLeakDetector, input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "4111111111111112",
            "AKIA",
            "AKIAIOSFODNN7EXAMPL",
            "sk-ab",
            "-----BEGIN PUBLIC KEY-----",
            "mongodb",
            "mysql://",
            "redis://",
            "https://example.com/db",
            "jdbc:mysql:thin@localhost",
        ] {
            assert!(
                DataLeakDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(DataLeakDetector.detect("").is_none());
        assert!(DataLeakDetector.detect("   ").is_none());
        assert!(DataLeakDetector.detect("カード番号は秘密です").is_none());
        assert!(
            DataLeakDetector
                .detect("card 4111 1111 1111 1111")
                .is_none()
        ); // spaced digits
    }
}
