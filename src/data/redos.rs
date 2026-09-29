// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::{AttackCategory, DetectionResult, Detector, Severity, regex_detect};
use regex::Regex;
use std::sync::LazyLock;

// 防御方视角：调用方准备把用户输入当正则编译时先扫一遍。
// 只挑无歧义会指数回溯的形态，宁可漏也不误杀。
// ponytail: 只做单层括号，`((a+))+` 这类深嵌套漏检——要覆盖得住上括号配对分析
// 七条分支合成一条 alternation：原先干净输入要顺序扫七条正则，而它们都以
// 字面量 `\(` 开头——1 MB 的全 `(` 输入里预筛每步都能命中，七遍加起来才是
// `paren_flood_stays_linear` 那份耗时里的大头。合成后只扫一遍。
// 七条都没有 flags，故无需逐条包裹。
static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    // 外层量词：`*` / `+` / `{n,}` 都会让内层量词的回溯次数相乘
    const Q: &str = r"(?:[+*?]|\{\d+,\})";
    // 被重复的原子限定为可打印 ASCII：真实正则的原子是 ASCII，而 `价格 (元+)* 说明`
    // 这类中文正文里的括号星号是散文，不是正则。非 ASCII 原子一律放过。
    Regex::new(
        &[
            // (a+)+ / (a*)* / (.+)+ / (\w+\s?)*：量词套量词
            r"\([!-~]{1,60}[+*?]\)[+*]",
            // (a+){2,}：量词套有界重复
            r"|\([!-~]{1,60}[+*?]\)\{\d+,\}",
            // (a{2,})* / (a{2,}){3,}：{n,} 套外层量词
            r"|\([!-~]{1,60}\{\d+,\}\)[+*]",
            r"|\([!-~]{1,60}\{\d+,\}\)\{\d+,\}",
            // (.|x)+ / (a|b|.)*：`.` 与任何分支重叠，必然回溯。只认 `|.` / `.|`
            // ——`.` 得是分支本身。写成"括号里有 `.`"会连 `(图 1.2)*` 这种脚注标记一起报。
            r"|\([!-~]{0,60}(?:\|\.|\.\|)[!-~]{0,60}\)",
            Q,
            // (\d|\w)* / (\w|y)*：字符类分支与落在类里的分支重叠。
            // ([0-9]|[a-z]) 这类互斥字符类不算，`(a|b)*` 这类互斥单字符更不算。
            r"|\(\\[dwsDWS]\|(?:\\[dwsDWS]|[A-Za-z0-9_])\)",
            Q,
            // (x|)* / (|x)*：空分支能匹配任何东西，与其余分支全重叠
            r"|\((?:[!-~]{0,60}\||\|[!-~]{0,60})\)",
            Q,
        ]
        .concat(),
    )
    .unwrap()
});

/// `regex` crate 没有反向引用，`(a|a)*`（分支相同）和 `(a|ab)*`（分支同前缀）只有逐字符
/// 比较才能判定——正则表达不了。只解析最外层括号、只看"首分支是单字符"的情形：它正是
/// 被"首分支 ≤1 字符即重叠"启发式误伤的那一类。返回命中的 `(` 位置与外层量词前面的长度。
fn repeated_prefix_branch(input: &str) -> Option<(usize, usize)> {
    // 每个 `(` 原本都从自己往后找 `)`，没有 `)` 时每次重扫到串尾——O(n²)：release 版
    // 1 MB 的 `(` 要 66 秒（本机 debug 实测 148 秒），可从请求体远程触发。先取最后一个
    // `)` 定上界（越过它的 `(` 不可能有配对），再缓存「下一个 `)`」：各次重扫的区间
    // 互不重叠，整体线性。
    let last_close = input.rfind(')')?;
    let mut next_close = input.find(')')?;
    for (open, _) in input.match_indices('(') {
        if open > last_close {
            break;
        }
        if open > next_close {
            next_close = open + input[open..].find(')')?;
        }
        let close = next_close;
        // 只认紧跟 * / + / {n,}（带逗号才算无上界，`{2}` 是有界重复，不爆炸）
        let tail = &input[close + 1..];
        let quant_len = match tail.chars().next() {
            Some('*' | '+') => 1,
            Some('{') => match tail.find('}') {
                Some(e) if tail[..e].contains(',') => e + 1,
                _ => 0,
            },
            _ => continue,
        };
        if quant_len == 0 {
            continue;
        }
        let mut branches = input[open + 1..close].split('|');
        // 首分支必须是单个 ASCII 字母数字：`[0-9]` 这类字符类分支不在本函数范围内
        let Some(first) = branches.next() else {
            continue;
        };
        let mut fc = first.chars();
        let (Some(c), None) = (fc.next(), fc.next()) else {
            continue;
        };
        if c.is_ascii_alphanumeric() && branches.any(|b| b.starts_with(c)) {
            return Some((open, quant_len));
        }
    }
    None
}

pub struct ReDoSDetector;

impl Detector for ReDoSDetector {
    fn name(&self) -> &'static str {
        "redos"
    }

    fn detect(&self, input: &str) -> Option<DetectionResult> {
        if let Some((open, quant_len)) = repeated_prefix_branch(input) {
            let end = input[open..]
                .find(')')
                .map_or(input.len(), |e| open + e + 1 + quant_len);
            return Some(DetectionResult {
                attack_type: self.name().to_string(),
                category: AttackCategory::Data,
                severity: Severity::Medium,
                matched_pattern: input[open..end].to_string(),
                offset: open,
                message: "Catastrophic backtracking pattern detected".into(),
            });
        }
        regex_detect(
            std::slice::from_ref(&*PATTERNS),
            self.name(),
            AttackCategory::Data,
            Severity::Medium,
            "Catastrophic backtracking pattern detected",
            input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{assert_clean, assert_detected};

    fn det() -> ReDoSDetector {
        ReDoSDetector
    }

    fn assert_hit(input: &str) {
        assert_detected(&det(), input, AttackCategory::Data, Severity::Medium);
    }

    #[test]
    fn name_is_redos() {
        assert_eq!(det().name(), "redos");
    }

    #[test]
    fn detects_nested_quantifiers() {
        for input in [
            "(a+)+",
            "(a*)*",
            "(.+)+",
            "([a-z]*)+",
            "(\\d+)+$",
            "^([a-zA-Z]+)*$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_nested_bounded_repeats() {
        for input in [
            "(a+){2,}",
            "(a{2,})*",
            "(a{2,}){3,}",
            "(\\d{1,}){1,}",
            "^(a{3,})+$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_overlapping_alternation() {
        for input in [
            "(a|a)*",
            "(.|x)+",
            "(\\w|y)*",
            "(x|)*",
            "(a|a){1,}",
            "^(a|b|.)*$",
        ] {
            assert_hit(input);
        }
    }

    #[test]
    fn detects_in_longer_expression() {
        for input in [r"^\s*(a+)+$", r"^(\w+\s?)*$", r"^([a-z]+)*$"] {
            assert_hit(input);
        }
    }

    #[test]
    fn ignores_safe_regexes() {
        for input in [
            r"^\d{4}-\d{2}-\d{2}$",
            r"^[a-z]+$",
            r"(GET|POST)",
            r"(GET|POST)*",
            r"(foo|bar)*",
            r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$",
            r"\(escaped\)+",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn ignores_disjoint_alternation() {
        // 分支互斥 = 没有回溯歧义，(a|b)* 是线性匹配。旧启发式只看"首分支 ≤1 字符"，
        // 把这类正常正则和中文正文里的括号星号全算成了 ReDoS。
        for input in [
            "(a|b)*",
            "(0|1)+",
            "(y|n)*",
            "(x|y|z)+",
            "^(a|b)+$",
            "(a|b){2,}",
            "(?i)(a|b)*",
            "选项(是|否)*",
            "步骤(1|2)*3",
            "价格 (元+)* 说明",
            "注意(重要+)*提醒",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn ignores_benign_inputs() {
        for input in [
            "Hello, this is a normal text input. Nothing suspicious here.",
            "5*(3+2)",
            "the (very) long text",
            "function(a, b)",
            "穿越之霸道总裁爱上我--重生之都市修仙",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn still_reports_same_prefix_branches() {
        // 分支相同 / 同前缀才是真重叠——`regex` crate 没有反向引用，这条走字符串比较
        for input in ["(a|a)*", "(a|ab)*", "(a|a){1,}"] {
            assert_hit(input);
        }
        // 有界重复 `{2}` 不爆炸
        assert_clean(&det(), "(a|a){2}");
    }

    /// 回归守卫：旧实现里每个 `(` 都从自己往后 `find(')')`，没有 `)` 时每次重扫到串尾，
    /// 复杂度 O(n²)：1 MB 的 `(` 要 66 秒 CPU（release 实测；本机 debug 实测 148 秒），
    /// 且来自请求体、可远程触发。
    ///
    /// 计时只压在「无 `)`」这一形态上：它的线性实现是一次 `rfind`（微秒级），比上限低
    /// 五个数量级，CI 再拥挤也撞不穿；O(n²) 则是上限的 15 倍。带 `)` 的形态线性开销是
    /// O(n) 次循环（毫秒级），在本机负载 9~14 / 8 核的环境里挂钟时间会被拉长几十倍
    /// （实测把 45 ms 拉过 3 秒），给它定上限必然误报——所以它只钉正确性。
    #[test]
    fn paren_flood_stays_linear() {
        use std::time::{Duration, Instant};
        // 1 MB 的 `(`，一个 `)` 都没有：正是报告里那个 66 秒的请求体
        let unclosed = "(".repeat(1_000_000);
        let t = Instant::now();
        let hit = repeated_prefix_branch(&unclosed);
        let elapsed = t.elapsed();
        assert!(hit.is_none(), "光有括号不是 ReDoS");
        assert!(
            elapsed < Duration::from_secs(10),
            "二次方重扫回来了：{} 个字符耗时 {elapsed:?}（线性实现是微秒级）",
            unclosed.len()
        );
        // 带 `)` 的形态（走缓存的 close）只钉正确性，不钉时间
        let closed = format!("{})", "(".repeat(200_000));
        assert!(repeated_prefix_branch(&closed).is_none());
    }

    /// 真实语料：代码与散文里的括号不该被当成 ReDoS。
    #[test]
    fn ignores_realistic_source_and_prose() {
        for input in [
            // Python 源码：大量括号、管道、量词，但没有嵌套量词
            "def summarize(items, limit=10):\n    names = [i.name for i in items if i.name]\n    top = names[:limit]\n    return (len(top), top)\n",
            "if (a or b) and not (c or d):\n    print((a, b))\n",
            "PATTERN = re.compile(r\"^[a-z0-9]+$\")  # (safe) no nested quantifier\n",
            // 工单 / 文档散文
            "步骤(1|2)*3 是笔误，正确写法是 (a|b)*，请核对",
            "价格 (元+)* 说明：括号里的加号是正文，不是正则",
            "See (a) and (b)* in the appendix; (x|y)* means repeat either.",
            "The customer wrote: 我的号码是 (010) 1234-5678, 请回电",
        ] {
            assert_clean(&det(), input);
        }
    }

    #[test]
    fn edge_cases() {
        assert_clean(&det(), "");
        assert_clean(&det(), "   ");
        assert_clean(&det(), "()");
        assert_clean(&det(), "()*");
        assert_clean(&det(), "(a)");
        // 量词在括号外但组内无重复——(really)* 是安全的
        assert_clean(&det(), "(really)*");
        // 已知缺口：深嵌套括号 + 长分支重叠看不到，单层括号启发式的上限
        assert_clean(&det(), r"^(([a-z])+.)+[A-Z]([a-z])+$");
        assert_clean(&det(), "^([0-9]|[0-9]){1,}$");
    }
}
