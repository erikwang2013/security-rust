// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use crate::result::{DetectionResult, Severity};
use std::fmt;

/// 风险评分：把单条低危信号聚合成可观测量，给 WAF 调误报留旋钮。
///
/// 派生顺序即强度顺序（None 最弱），与 `Severity` 相反——那边声明顺序是递减的，
/// 所以故意没派生 `Ord`。这里不要跟 `Severity` 混用 `max()`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RiskLevel::None => "NONE",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        })
    }
}

/// 显式权重表。`Severity` 没有 `Ord`（声明顺序是 Critical→Low 递减），
/// 给它加 `Ord` 会让 `max()` 静默取到最轻的那条，所以权重写在评分侧。
fn weight(severity: &Severity) -> u32 {
    match severity {
        Severity::Critical => 100,
        Severity::High => 40,
        Severity::Medium => 15,
        Severity::Low => 5,
    }
}

/// 原始风险分：所有命中按权重累加。
pub fn total(results: &[DetectionResult]) -> u32 {
    results.iter().map(|r| weight(&r.severity)).sum()
}

/// 聚合等级。
///
/// - 空结果 → `None`
/// - 任一 `Severity::Critical` → `Critical`（短路，不靠累加）
/// - 否则按总分分档，多条低危叠加可升级（3×Low = 15 → Medium，8×Low = 40 → High）
pub fn score(results: &[DetectionResult]) -> RiskLevel {
    if results.is_empty() {
        return RiskLevel::None;
    }
    if results.iter().any(|r| r.severity == Severity::Critical) {
        return RiskLevel::Critical;
    }
    level_of(total(results))
}

fn level_of(points: u32) -> RiskLevel {
    match points {
        0 => RiskLevel::None,
        1..=14 => RiskLevel::Low,
        15..=39 => RiskLevel::Medium,
        40..=99 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

/// 评分结果：等级、原始分、参与聚合的命中条数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score: u32,
    pub results: usize,
}

/// 一次算出等级与原始分，省得调用方算两遍。
pub fn assess(results: &[DetectionResult]) -> RiskAssessment {
    RiskAssessment {
        level: score(results),
        score: total(results),
        results: results.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::AttackCategory;

    fn hit(severity: Severity) -> DetectionResult {
        DetectionResult {
            attack_type: "test".into(),
            category: AttackCategory::Injection,
            severity,
            matched_pattern: "x".into(),
            offset: 0,
            message: "test".into(),
        }
    }

    fn hits(severities: &[Severity]) -> Vec<DetectionResult> {
        severities.iter().map(|s| hit(s.clone())).collect()
    }

    fn repeated(severity: Severity, n: usize) -> Vec<DetectionResult> {
        (0..n).map(|_| hit(severity.clone())).collect()
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(score(&[]), RiskLevel::None);
        assert_eq!(total(&[]), 0);
        assert_eq!(
            assess(&[]),
            RiskAssessment {
                level: RiskLevel::None,
                score: 0,
                results: 0
            }
        );
    }

    #[test]
    fn single_critical_is_critical() {
        assert_eq!(score(&hits(&[Severity::Critical])), RiskLevel::Critical);
    }

    #[test]
    fn critical_short_circuits_even_with_low() {
        assert_eq!(
            score(&hits(&[Severity::Low, Severity::Critical, Severity::Low])),
            RiskLevel::Critical
        );
    }

    #[test]
    fn single_low_does_not_escalate() {
        assert_eq!(score(&hits(&[Severity::Low])), RiskLevel::Low);
        assert_eq!(score(&hits(&[Severity::Medium])), RiskLevel::Medium);
        assert_eq!(score(&hits(&[Severity::High])), RiskLevel::High);
    }

    #[test]
    fn stacked_lows_escalate() {
        // 5+5 = 10 → 还是 Low
        assert_eq!(
            score(&hits(&[Severity::Low, Severity::Low])),
            RiskLevel::Low
        );
        // 5*3 = 15 → Medium
        assert_eq!(
            score(&hits(&[Severity::Low, Severity::Low, Severity::Low])),
            RiskLevel::Medium
        );
        // 5*8 = 40 → High
        assert_eq!(
            score(&repeated(Severity::Low, 8)),
            RiskLevel::High,
            "8 × Low 应升级到 High"
        );
    }

    #[test]
    fn stacked_mediums_and_highs_escalate() {
        // 15*3 = 45 → High
        assert_eq!(score(&repeated(Severity::Medium, 3)), RiskLevel::High);
        // 40*3 = 120 → Critical
        assert_eq!(score(&repeated(Severity::High, 3)), RiskLevel::Critical);
        // 40 + 5 = 45 → High
        assert_eq!(
            score(&hits(&[Severity::High, Severity::Low])),
            RiskLevel::High
        );
    }

    #[test]
    fn boundaries() {
        assert_eq!(level_of(0), RiskLevel::None);
        assert_eq!(level_of(1), RiskLevel::Low);
        assert_eq!(level_of(14), RiskLevel::Low);
        assert_eq!(level_of(15), RiskLevel::Medium);
        assert_eq!(level_of(39), RiskLevel::Medium);
        assert_eq!(level_of(40), RiskLevel::High);
        assert_eq!(level_of(99), RiskLevel::High);
        assert_eq!(level_of(100), RiskLevel::Critical);
    }

    #[test]
    fn assessment_carries_counts_and_points() {
        let a = assess(&hits(&[Severity::High, Severity::Low, Severity::Low]));
        assert_eq!(a.results, 3);
        assert_eq!(a.score, 50);
        assert_eq!(a.level, RiskLevel::High);
    }

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::None < RiskLevel::Low);
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn risk_level_display_uppercase() {
        assert_eq!(RiskLevel::None.to_string(), "NONE");
        assert_eq!(RiskLevel::Low.to_string(), "LOW");
        assert_eq!(RiskLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(RiskLevel::High.to_string(), "HIGH");
        assert_eq!(RiskLevel::Critical.to_string(), "CRITICAL");
    }
}
