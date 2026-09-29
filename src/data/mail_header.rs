// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

/// 强信号：要求的是**结构异常**，不是「某个头名出现过」。
/// 实测 39 条输入（tests/real_world_corpus.rs 的 16 条 + 转发邮件 / 邮件原文 / 邮件日志 /
/// 带 `From:` 头的 HTTP 请求等探针 16 条 + 本仓库 README / docs / 源码 7 份）：
/// 两条强档一共命中 4 条——2 条攻击样例，外加 2 条已知残留（粘贴整封 MIME 来信原文、
/// HTTP 请求带两个 `From:` 头），见 `pasted_mime_mail_is_medium_via_mime_version_header`。
static STRONG_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    // 两条分支的 flags 完全一致（`(?m)(?i)`），提到最前面即可，无需逐条包裹。
    Regex::new(
        &[
            // 双发件人：相邻两行各是一个 `From:` 头。两处都锚行首——`Set the From: address.` 这种
            // 句子里的 `From:` 不算，认的是「相邻两个 From: 头」这个结构。正常邮件、转发邮件、
            // 引用回复都只有一个 `From:`。
            r"(?mi)^From\s*:.*\r?\n^From\s*:",
            // `MIME-Version:` 只出现在真正的 MIME 报文里：RFC 2045 定义它，HTTP 的字段表
            // （RFC 7231）里没有这个名字，所以行首出现即邮件结构信号。
            // 必须锚行首：README.md / docs/OWASP-COVERAGE.md 的表格里写着 `MIME-Version:` 来介绍
            // 本检测器，未锚版实测把本库自己的 README 判成 Medium（与 pet.svg 同一类误报）。
            r"|^MIME-Version\s*:",
            // 曾有 `(?i)Content-Type\s*:.*multipart`——`Content-Type: multipart/form-data` 是每个
            // 文件上传 POST 的标准头，与邮件正文同形。检测器分不清 HTTP 请求和邮件，删。
            // 连带代价：`boundary=` 也随之不再被覆盖（它只在 multipart 上下文里才有意义，
            // 而那个上下文已经不作为信号），没有 `MIME-Version:` 的裸 multipart 片段不再命中。
        ]
        .concat(),
    )
    .unwrap()
});

/// 弱信号：行首的 `Cc:` / `Bcc:` 是**正常抄送头与注入头逐字节同形**的那一类。
/// 转发邮件（`---------- Forwarded message ---------` 紧接着就是 `Cc: …`）、客服系统摄入的
/// 来信、邮件原文粘贴，全都带行首 `Cc:`；正则分不出「粘贴进来的来信」和「注入的头」。
/// 收紧不了（要认的就是这个字节序列），故报 Low：仍然命中、不静默漏报，但单条 5 分不单独
/// 触发拒绝，是否升级交给调用方按聚合分决定。
static WEAK_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    // 同强档：两条分支 flags 一致，提到最前面。
    // 抄送头必须是行首：`Please cc: my manager` 是散文，注入才是 `\r\nCc: ...`
    Regex::new(r"(?mi)^Bcc\s*:|^Cc\s*:").unwrap()
});

pub struct MailHeaderDetector;

impl Detector for MailHeaderDetector {
    fn name(&self) -> &'static str {
        "mail_header"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*STRONG_PATTERNS),
            self.name(),
            AttackCategory::Data,
            Severity::Medium,
            "Mail header injection detected",
            input,
        )
        .or_else(|| {
            regex_detect(
                std::slice::from_ref(&*WEAK_PATTERNS),
                self.name(),
                AttackCategory::Data,
                Severity::Low,
                "Recipient header present (weak signal)",
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
        assert_eq!(MailHeaderDetector.name(), "mail_header");
    }

    /// 攻击方向：行首的抄送头仍然检出。severity 由 Medium 降为 Low —— 因为
    /// 「行首 `Cc:`」与转发邮件 / 邮件原文里的正常抄送头逐字节同形，见
    /// `recipient_headers_are_weak_signals` 里的良性对照。
    #[test]
    fn detects_injected_recipient_headers() {
        for payload in [
            "Bcc: victim@evil.com",
            "Cc: victim@evil.com",
            "bcc: lower@case.com",
        ] {
            let r = MailHeaderDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.attack_type, "mail_header");
            assert_eq!(r.category, AttackCategory::Data);
            assert_eq!(r.severity, Severity::Low);
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

    /// 强档两方向之一：攻击形态仍是 Medium（`From:` 重复 / 行首 `MIME-Version:`）。
    /// 抄送头（`Cc:` / `Bcc:`）已移到弱档，见 `recipient_headers_are_weak_signals`。
    #[test]
    fn detects_double_from_and_mime_headers() {
        for payload in [
            "From: a@b.c\nFrom: c@d.e",
            "From: a@b.c\r\nFrom: c@d.e",
            // 注入形态：两个 From: 头各占一行
            "victim@example.com\r\nFrom: attacker@evil.com\r\nFrom: attacker2@evil.com",
            "MIME-Version: 1.0",
            // 注入形态：换行后的行首 MIME 头
            "victim@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed",
            // 真实 MIME 邮件：`Content-Type: multipart` 不再是信号后，靠 `MIME-Version:` 命中
            "Return-Path: <a@b.c>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"----=_x\"\n\n--x--\n",
        ] {
            let r = MailHeaderDetector
                .detect(payload)
                .unwrap_or_else(|| panic!("expected detection for {:?}", payload));
            assert_eq!(r.severity, Severity::Medium, "payload {:?}", payload);
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

    /// 弱档两方向：抄送头注入仍然检出（不静默漏报），但报 Low；
    /// 与它逐字节同形的良性输入（转发邮件正文、邮件原文）同样只到 Low，不单独拒绝。
    /// 降档理由见 `WEAK_PATTERNS` 的注释。
    #[test]
    fn recipient_headers_are_weak_signals() {
        for input in [
            // 攻击：注入的抄送头
            "victim@example.com\r\nCc: attacker@evil.com",
            "victim@example.com\r\nBcc: attacker@evil.com",
            // 良性：转发的邮件正文——`Cc:` 就在行首，与上面那条注入无法区分
            "FYI, see below.\n\n---------- Forwarded message ---------\n\
             From: alice@example.com\nDate: Mon, 1 Sep 2026 09:00\nSubject: Re: invoice 4821\n\
             To: bob@example.com\nCc: carol@example.com\n\nThanks!\n",
            // 良性：客服系统摄入的来信原文（非 MIME，没有 `MIME-Version:` 头）
            "From: Alice <alice@example.com>\nTo: Bob <bob@example.com>\n\
             Cc: Carol <carol@example.com>\nSubject: Re: invoice\n\nSee attached.\n",
        ] {
            let r = MailHeaderDetector
                .detect(input)
                .unwrap_or_else(|| panic!("expected weak-signal detection for {:?}", input));
            assert_eq!(r.severity, Severity::Low, "input {:?}", input);
        }
    }

    /// 已知残留（待定，不是疏漏）：粘贴进来的**真实 MIME 来信**在行首带 `MIME-Version:`，
    /// 仍会命中强档 Medium（15 分）。它单独不越过拒绝线（15 < 40），但会参与叠加。
    /// 保留它的理由：这是本检测器唯一还能认出「MIME 报文结构」的信号，删掉后
    /// mail_header 对 MIME 注入完全无感（`Content-Type: multipart` 已于上一轮删除，
    /// 见 `STRONG_PATTERNS` 注释）。实测 `MIME-Version:` 不出现在 HTTP 请求头里，
    /// 所以这条 FP 只在「把整封信原文喂给扫描器」时出现。
    #[test]
    fn pasted_mime_mail_is_medium_via_mime_version_header() {
        let input = "From: Alice <alice@example.com>\nTo: Bob <bob@example.com>\n\
                     Cc: Carol <carol@example.com>\nBcc: Dave <dave@example.com>\n\
                     Subject: Re: invoice\nMIME-Version: 1.0\n\
                     Content-Type: text/plain; charset=utf-8\n\nSee attached.\n";
        let r = MailHeaderDetector.detect(input).expect("detection");
        assert_eq!(r.severity, Severity::Medium);
        assert_eq!(r.matched_pattern, "MIME-Version:");
    }

    /// 强档两方向之二：收紧后必须**完全干净**的良性输入——本库自己的文档表格、
    /// 散文里提到的头名、句中（非行首）的 `From:` 对。
    /// 前两条实测：未锚行首的 `MIME-Version\s*:` 会把 README.md / docs/OWASP-COVERAGE.md
    /// 判成 Medium（score=15）——和 pet.svg 一样，是「检测器扫不动自己的文档」。
    #[test]
    fn doc_tables_and_prose_mentions_are_clean() {
        for input in [
            // README.md:173 原文（本检测器的介绍行）
            "| **mail_header** | `Bcc:`/`Cc:` 密送注入、`From:` 多重发件人、`MIME-Version:`/`Content-Type: multipart` MIME 头注入、`boundary=` 边界操纵 | Medium |",
            // docs/OWASP-COVERAGE.md:72 原文
            "| `mail_header` | `Bcc:` / `Cc:` / `MIME-Version:` / `boundary=`、`Content-Type: ...multipart`、重复 `From:` |",
            // 散文里提到头名（`MIME-Version:` 不在行首）
            "For MIME-Version: see the docs.",
            "The cc: field on the signup page is broken.",
            // 句中出现的两个 `From:`（不是相邻两行的头）
            "Set the From: address first.\nThen the From: line is filled automatically.",
        ] {
            crate::test_helpers::assert_clean(&MailHeaderDetector, input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input.",
            "Bcc victim@evil.com",
            "From: a@b.c",
            "Content-Type: text/plain",
            "boundary abc",
            "MIME-Version",
            "multipart/form-data",
        ] {
            assert!(
                MailHeaderDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    /// 真实语料：`cc:` / `boundary=` 出现在散文里不是邮件头。裸模式实测把这类工单文字
    /// 报成 Medium（score=15，命中的是 `cc:`）；Medium 每条 15 分、3 条即到 40 分的
    /// 拒绝线（`risk.level >= High`），散文里一个 `cc:` 就是白送的 15 分。
    #[test]
    fn ignores_prose_mentions_and_benign_emails() {
        for input in [
            "Please cc: my manager on this reply.",
            "boundary=0.5",
            "The boundary=0.5 is the decision threshold, cc: the QA list too.",
            // 工单 / 支持记录：同一类型文字里的 `cc:` 与 `boundary=`
            "Customer note: please cc: billing when the ticket boundary=0.5 is exceeded. \
             We also CC: nobody — see the FAQ (cc: means carbon copy).",
            // 最普通的文件上传请求：`Content-Type: multipart/form-data` 曾经让每个上传
            // POST 白得 15 分，是越线的最佳配料。这是必须保持干净的负控。
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: multipart/form-data; boundary=----x\r\nContent-Length: 1024\r\n\r\n",
            // 同一形态的变体（无 Content-Length / 带 Authorization）
            "POST /api/files HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer abc\r\n\
             Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\r\n",
            // 覆盖率取舍（已批准）：不带 `MIME-Version:` 的裸 multipart 邮件片段不再命中——
            // 它与上传请求在字节层面同形，正则分不出，只能选一边。真实 MIME 邮件带
            // `MIME-Version:`，仍在上面的命中列表里。
            "Content-Type: multipart/mixed; boundary=abc123",
            "boundary=abc123",
            // 真实来信（非 MIME）：头 + 正文都没有本检测器该报的东西
            "From: customer@example.com\nSubject: Re: order 1234\nDate: Mon, 1 Sep 2026 10:00:00 +0800\n\n\
             Hi, please cc: my manager on this reply.\nThanks,\nDana\n",
        ] {
            assert!(
                MailHeaderDetector.detect(input).is_none(),
                "false positive: {:?}",
                input
            );
        }
    }

    #[test]
    fn edge_cases() {
        assert!(MailHeaderDetector.detect("").is_none());
        assert!(MailHeaderDetector.detect("   ").is_none());
        assert!(
            MailHeaderDetector
                .detect("ＢＣＣ: evil@example.com")
                .is_none()
        ); // fullwidth letters
    }
}
