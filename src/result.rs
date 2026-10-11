// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use std::fmt;

/// 单条命中的严重度。声明顺序**从重到轻**（与
/// [`RiskLevel`](crate::score::RiskLevel) 相反），因此故意不派生 `Ord`：
/// 拿 `max()` 取"最严重"会静默取到最轻的那条，聚合权重写在 `score` 侧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

/// 攻击所属的四大类，与 `src/` 下四个检测器模块一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackCategory {
    Injection,
    Protocol,
    Data,
    File,
}

/// 小写的分类标签，供日志直接打印。不是处置结论，故不跟 [`Severity`] 的大写风格。
impl fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackCategory::Injection => write!(f, "injection"),
            AttackCategory::Protocol => write!(f, "protocol"),
            AttackCategory::Data => write!(f, "data"),
            AttackCategory::File => write!(f, "file"),
        }
    }
}

/// 一条命中：字段是只读快照，切片、告警、审计日志都从这里取，库自身不解释处置动作。
///
/// 两个对调用方有实际后果的契约：
/// - **每个检测器对同一输入至多产出一条**：同一个 `attack_type` 不会重复出现。
///   有强弱两档的检测器先试强档，未中再试弱档，两档共用同一个 `attack_type`，
///   只有 [`severity`](DetectionResult::severity) 不同。
/// - **弱信号固定报 [`Severity::Low`]**，单独不足以构成拒绝理由，详见 `severity` 字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// 检测器名，与 [`Detector::name`](crate::Detector::name) 逐字相等
    /// （`tests/invariants.rs` 对 32 个检测器逐一核验）；同时是
    /// [`Scanner::scan_with`](crate::Scanner::scan_with) 的过滤键。
    pub attack_type: String,
    /// 四大类之一：注入 / 协议 / 数据 / 文件。
    pub category: AttackCategory,
    /// 严重度。**弱信号（weak signal）固定为 [`Severity::Low`]（5 分）**：
    /// `Low` 不单是"轻"，更是"该形态单独出现是正常内容的常态"—— 正常网页里的
    /// `<script src=...>`、源码里的单级 `../` 都落这一档，因此
    /// **单条弱信号不得构成拒绝理由**（参考流水线的拒绝线是
    /// `risk.level >= RiskLevel::High`，40 分）。弱信号仍然被检出、照常计入
    /// [`Scanner::assess`](crate::Scanner::assess) 的累加，要不要拒绝看聚合分：
    /// 多条弱信号叠加会升级（3×Low = 15 → Medium，8×Low = 40 → High）。
    pub severity: Severity,
    /// 命中的具体片段，恰好是 `&input[offset..offset + matched_pattern.len()]`，
    /// 调用方可直接用它给用户标红。
    pub matched_pattern: String,
    /// `matched_pattern` 在输入中的**字节**偏移（UTF-8 字节下标，不是字符数）。
    pub offset: usize,
    /// 人类可读说明（英文，供日志直接打印）。
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DetectionResult {
        DetectionResult {
            attack_type: "xss".into(),
            category: AttackCategory::Injection,
            severity: Severity::Critical,
            matched_pattern: "<script>".into(),
            offset: 0,
            message: "XSS detected".into(),
        }
    }

    #[test]
    fn severity_display_uppercase() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::Low.to_string(), "LOW");
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_ne!(Severity::Critical, Severity::High);
        assert_ne!(Severity::Medium, Severity::Low);
    }

    #[test]
    fn attack_category_display_tags() {
        assert_eq!(AttackCategory::Injection.to_string(), "injection");
        assert_eq!(AttackCategory::Protocol.to_string(), "protocol");
        assert_eq!(AttackCategory::Data.to_string(), "data");
        assert_eq!(AttackCategory::File.to_string(), "file");
    }

    #[test]
    fn attack_category_equality() {
        assert_eq!(AttackCategory::Injection, AttackCategory::Injection);
        assert_ne!(AttackCategory::Injection, AttackCategory::Protocol);
        assert_ne!(AttackCategory::Data, AttackCategory::File);
    }

    #[test]
    fn detection_result_clone_and_equality() {
        let a = sample();
        assert_eq!(a, a.clone());
    }

    #[test]
    fn detection_result_field_difference_changes_equality() {
        let a = sample();
        let b = DetectionResult {
            severity: Severity::High,
            ..a.clone()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn detection_result_debug_output() {
        let dbg = format!("{:?}", sample());
        assert!(dbg.contains("xss"));
        assert!(dbg.contains("Injection"));
        assert!(dbg.contains("CRITICAL") || dbg.contains("Critical"));
    }
}
