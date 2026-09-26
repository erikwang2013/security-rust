// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 项目宠物：**甲哨 Sentri**。
//!
//! 本模块不含逻辑，只有形象本身 —— 文档、示例、下游的 WAF 管理界面用同一份，
//! 不必各自抄一遍。形象文件在 `docs/pet.svg`，终端里用 [`ASCII`]。
//!
//! ```text
//!       (o)(o)
//!    ⌕┬─────────┬!     甲哨 Sentri
//!     │ · · · · │       只报告，不拦截
//!     └──┬───┬──┘       32 detectors / 4 categories
//!       /     \         deps = regex ×1
//! ```
//!
//! 人设取自本库的设计：32 片甲就是 32 个检测器，四行甲片是四大类；左钳拿放大镜
//! 负责**看**，右钳举告示牌负责**报**，但两只钳子都不替调用方做决定。
//! 唯一的例外是 [`SessionGuard`](crate::session::SessionGuard) —— 它会真的 Block。

/// 项目宠物名：中文名 + 英文名。
pub const NAME: &str = "甲哨 Sentri";

/// 一句话人设。
pub const TAGLINE: &str = "只报告，不拦截";

/// ASCII 版形象，给终端、日志、示例 banner 用。
pub const ASCII: &str = r#"      (o)(o)
   ⌕┬─────────┬!     甲哨 Sentri
    │ · · · · │       只报告，不拦截
    └──┬───┬──┘       32 detectors / 4 categories
      /     \         deps = regex ×1"#;

/// SVG 版形象（`docs/pet.svg`），给 README 与下游界面用。
pub const SVG: &str = include_str!("../docs/pet.svg");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttackCategory;
    use regex::Regex;

    #[test]
    fn svg_is_bundled_whole() {
        assert!(SVG.starts_with("<svg"), "svg 头部: {:?}", &SVG[..40]);
        assert!(SVG.trim_end().ends_with("</svg>"));
        assert!(SVG.contains(r#"viewBox="0 0 480 460""#), "viewBox 变了");
    }

    /// 形象与库的对账：四行甲片 = 四大类，甲片总数 = 检测器总数。
    ///
    /// 认账目不认画法：每行甲片带一句 `<!-- 类别: N detectors, M plates -->` 注记，
    /// N 是该类**检测器**数（要对得上 [`AttackCategory`]），M 是该行声明画出的
    /// 甲片数。两列分开写是因为它们本就不相等——注入 11 个检测器只画 8 片甲，
    /// 甲片按类别配色，不按数量铺满；对账只认总数。
    ///
    /// 改半径、配色、坐标都不该让这里变红 —— 数 `r="5"` 是把画法当账目，加一个
    /// 装饰圆就能骗过它。少画一片甲、注记与画面对不上、类别名不认账才该红。
    /// crate 侧的 32 由 `scanner::tests` 自己看着。
    #[test]
    fn plates_account_for_every_detector() {
        let row =
            Regex::new(r"<!-- (\w+): (\d+) detectors, (\d+) plates -->\s*((?:<circle[^>]*/>\s*)+)")
                .unwrap();
        let rows: Vec<(String, usize, usize, usize)> = row
            .captures_iter(SVG)
            .map(|c| {
                (
                    c[1].to_string(),
                    c[2].parse().unwrap(),           // 该类检测器数
                    c[3].parse().unwrap(),           // 注记声明的甲片数
                    c[4].matches("<circle").count(), // 实际画出的甲片数
                )
            })
            .collect();

        let names: Vec<&str> = rows.iter().map(|(name, ..)| name.as_str()).collect();
        for category in [
            AttackCategory::Injection,
            AttackCategory::Protocol,
            AttackCategory::Data,
            AttackCategory::File,
        ] {
            assert!(
                names.contains(&category.to_string().as_str()),
                "形象里少了 `{category}` 那一行甲片（注记格式：`<!-- 类别: N detectors, M plates -->`）"
            );
        }
        assert_eq!(names.len(), 4, "四行甲片 = 四大类，多出来的行: {names:?}");

        for (name, _, declared_plates, drawn) in &rows {
            assert_eq!(
                declared_plates, drawn,
                "`{name}` 那行：注记声明 {declared_plates} 片，实际画了 {drawn} 片"
            );
        }
        let declared: usize = rows.iter().map(|(_, detectors, ..)| detectors).sum();
        let drawn: usize = rows.iter().map(|(_, _, _, plates)| plates).sum();
        assert_eq!(declared, 32, "注记里的检测器总数");
        assert_eq!(drawn, 32, "画出来的甲片总数 —— 32 片甲 = 32 个检测器");
    }

    #[test]
    fn ascii_and_name_are_not_empty() {
        assert!(!NAME.is_empty() && !TAGLINE.is_empty());
        assert!(ASCII.lines().count() >= 5);
    }
}
