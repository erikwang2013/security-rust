// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::store::ThrottleStore;
use super::{StoreError, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

/// 滑动窗口限流 / 封禁闸门。
///
/// ## key 由调用方构造
///
/// `key` 是计数桶的名字，本模块只把它当作不透明字符串。约定形如
/// `format!("ip:{}", ip)`（按来源）或 `format!("acct:{}", user)`（按账户）；
/// 两类 key 前缀不同，天然互不干扰，可同时启用。
///
/// **不要把用户输入直接当 key**：拿请求里原样的用户名 / 任意 header 当 key，
/// 攻击者只要每次换一个值就能把自己拆成无限多个桶，限流形同虚设；
/// 空 key 同理，会让所有构造失败的请求共用同一个桶。调用方须先规范化
/// （截断长度、统一大小写、限制字符集），并保证 key 非空。
pub struct Throttle<S: ThrottleStore> {
    store: S,
    config: ThrottleConfig,
}

impl<S: ThrottleStore> Throttle<S> {
    pub fn new(store: S, config: ThrottleConfig) -> Self {
        Self { store, config }
    }

    pub fn config(&self) -> &ThrottleConfig {
        &self.config
    }

    /// 请求进入时调用。先查封禁，再算剩余额度。
    ///
    /// 存储报错 → `ThrottleDecision::Unavailable`（见该变体的说明，**不 fail-closed**）：
    /// 这里是限流的纵深防御，不是主认证闸门。后端故障时返回 `Banned` 会把全体
    /// 用户挡在门外（自我 DoS，且攻击者可能主动诱发），而放行只是暂时失去
    /// 暴力破解防护 —— 主认证闸门 `SessionGuard` 仍然在拦。调用方拿到
    /// `Unavailable` 后自行选择，建议放行 + 告警。
    pub fn check(&self, key: &str, now: u64) -> ThrottleDecision {
        match self.store.is_banned(key, now) {
            // 自己比对 `now`，不假定后端已过滤：后端若返回原始值（第三方的
            // Redis 实现常见的做法），直接信它就等于把 key 永久锁死。
            Ok(Some(until)) if until > now => ThrottleDecision::Banned { until },
            Ok(_) => match self.store.failure_count(key, now, self.config.window_secs) {
                Ok(count) => ThrottleDecision::Allow {
                    remaining: self.remaining(count),
                },
                Err(_) => ThrottleDecision::Unavailable,
            },
            Err(_) => ThrottleDecision::Unavailable,
        }
    }

    /// 同时检查多个维度（如 `[ip_key, account_key]`），返回最严格的结果。
    ///
    /// 合并规则（严格度）：任一 `Banned` → `Banned`（取最晚的 `until`）；
    /// 否则任一 `Unavailable` → `Unavailable`；否则 `Allow` 取**最小** `remaining`。
    ///
    /// 每个 key 各自独立查询，**不合并计数**：`ip:` 与 `acct:` 是两类互不干扰的桶，
    /// 合并会让 NAT 后面的其他人替攻击者吃掉额度。
    ///
    /// 空 `keys` 什么都查不到，返回 `Allow { remaining: 0 }` 而非满额 —— 这个数字
    /// 会被写进 X-RateLimit-* 响应头，凭空报满额等于谎报额度。
    pub fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision {
        let mut banned_until: Option<u64> = None;
        let mut unavailable = false;
        let mut min_remaining: Option<u32> = None;
        for key in keys {
            match self.check(key, now) {
                ThrottleDecision::Banned { until } => {
                    // 不能提前返回：规则要求取「最晚」的解封时刻，得扫完所有 key
                    banned_until = Some(banned_until.map_or(until, |b: u64| b.max(until)));
                }
                ThrottleDecision::Unavailable => unavailable = true,
                ThrottleDecision::Allow { remaining } => {
                    min_remaining = Some(min_remaining.map_or(remaining, |r| r.min(remaining)));
                }
            }
        }
        if let Some(until) = banned_until {
            return ThrottleDecision::Banned { until };
        }
        if unavailable {
            return ThrottleDecision::Unavailable;
        }
        ThrottleDecision::Allow {
            remaining: min_remaining.unwrap_or(0),
        }
    }

    /// 认证失败时调用。达到 threshold 就封禁并返回 `Banned`，否则返回 `Allow { remaining }`。
    ///
    /// 返回 [`ThrottleOutcome`] 而非 `ThrottleDecision`：这里**不存在** `Unavailable`
    /// —— 存储故障走 `Err`，两个可达状态对应两个分支，调用方不必再写一个永不执行的
    /// 第三个臂。判断「要不要拦这个请求」用 [`Throttle::check_any`]。
    ///
    /// 判定顺序：先拿窗口内计数，`count >= threshold` 时写封禁并返回解封时刻。
    /// `threshold` 是「第几次失败触发封禁」，因此第 `threshold` 次调用返回的是
    /// `Banned` 而不是 `Allow { remaining: 0 }` —— 剩余额度为 0 的那次已经是拒绝。
    ///
    /// 注意 `record_failure`（计数）与 `ban`（封禁）是两次独立的锁获取，**不原子**：
    /// 两者之间并发一次 `reset` 是可能的，结果是刚认证成功的用户又被封上
    /// （可用性问题，不构成绕过 —— 计数也确实已经记下了）。若那个窗口不可接受，
    /// 得把「计数 + 判阈值 + 写封禁」并成一个 store 操作。
    ///
    /// 同理，`ban` 写失败时计数已经落库：本调用返回 `Err`，但下一步 `check`
    /// 会看到 `Allow { remaining: 0 }`（额度确实耗尽），由调用方据此拒绝。
    pub fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError> {
        let count = self
            .store
            .record_failure(key, now, self.config.window_secs)?;
        if count >= self.config.threshold {
            let until = now.saturating_add(self.config.ban_secs);
            self.store.ban(key, until)?;
            return Ok(ThrottleOutcome::Banned { until });
        }
        Ok(ThrottleOutcome::Allow {
            remaining: self.remaining(count),
        })
    }

    /// 认证成功时调用：**只清失败计数，保留封禁**。
    ///
    /// 「凭据正确 ⇒ 不是暴力破解 ⇒ 顺手解封」只对 `acct:` 桶成立。对 `ip:` 这类
    /// 共享桶，封禁是 NAT / 代理后面的所有人共用的 —— 换成 `reset`（清计数 + 清封禁）
    /// 意味着桶里**任意**另一个用户认证成功，就能替爆破者解除封禁并洗掉计数。
    ///
    /// 这是有意的安全取舍，不是漏写的细节：代价是账户桶下用户被爆破牵连时，
    /// 即使立刻输对密码也要等满 `ban_secs`（默认 900 秒）才恢复；换来的是共享桶的
    /// 封禁不会被他人一次成功认证解除。封禁不需要在这里额外清理，`is_banned` 的
    /// `now` 过滤会让它自然到期；要人工提前解封用 [`Throttle::reset`]。
    pub fn record_success(&self, key: &str) -> Result<(), StoreError> {
        self.store.clear_failures(key)
    }

    /// 人工解封 / 解限。
    pub fn reset(&self, key: &str) -> Result<(), StoreError> {
        self.store.reset(key)
    }

    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.store.purge_expired(now)
    }

    /// 剩余可失败次数。计数已超阈值（如封禁过期但失败仍在窗口内）时钳到 0。
    fn remaining(&self, count: u32) -> u32 {
        self.config.threshold.saturating_sub(count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::MemoryThrottleStore;
    use super::*;

    const NOW: u64 = 1_000_000;

    fn throttle(threshold: u32, window_secs: u64, ban_secs: u64) -> Throttle<MemoryThrottleStore> {
        Throttle::new(
            MemoryThrottleStore::new(),
            ThrottleConfig {
                threshold,
                window_secs,
                ban_secs,
            },
        )
    }

    #[test]
    fn config_accessor_returns_construction_config() {
        let t = throttle(3, 60, 900);
        assert_eq!(t.config().threshold, 3, "got {:?}", t.config());
        assert_eq!(t.config().window_secs, 60, "got {:?}", t.config());
        assert_eq!(t.config().ban_secs, 900, "got {:?}", t.config());
    }

    #[test]
    fn throttle_is_generic_over_store() {
        // 只绑定 ThrottleStore trait，便于多实例部署换后端
        fn accepts<S: ThrottleStore>(t: &Throttle<S>) -> u32 {
            t.config().threshold
        }
        let t = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
        assert_eq!(accepts(&t), 5);
    }

    #[test]
    fn check_on_fresh_key_is_full_budget() {
        let t = throttle(5, 60, 900);
        assert_eq!(
            t.check("ip:1.2.3.4", NOW),
            ThrottleDecision::Allow { remaining: 5 },
            "窗口为空时剩余额度应为满额"
        );
    }

    #[test]
    fn check_does_not_consume_budget() {
        let t = throttle(5, 60, 900);
        for _ in 0..10 {
            assert_eq!(
                t.check("ip:a", NOW),
                ThrottleDecision::Allow { remaining: 5 }
            );
        }
        assert_eq!(
            t.record_failure("ip:a", NOW).unwrap(),
            ThrottleOutcome::Allow { remaining: 4 },
            "check 不该计入失败"
        );
    }

    #[test]
    fn check_reports_decremented_remaining() {
        let t = throttle(5, 60, 900);
        t.record_failure("ip:a", NOW).unwrap();
        t.record_failure("ip:a", NOW).unwrap();
        assert_eq!(
            t.check("ip:a", NOW),
            ThrottleDecision::Allow { remaining: 3 },
            "放行时的剩余额度要反映窗口内已累计的失败"
        );
    }

    #[test]
    fn ban_outlives_the_counting_window() {
        // 封禁时长 > 窗口：计数滑出后仍应保持封禁
        let t = throttle(1, 60, 900);
        t.record_failure("ip:a", NOW).unwrap();
        assert_eq!(
            t.check("ip:a", NOW + 61),
            ThrottleDecision::Banned { until: NOW + 900 },
            "窗口滑出不影响封禁"
        );
    }

    #[test]
    fn purge_expired_delegates_to_store() {
        let t = throttle(5, 60, 900);
        t.record_failure("ip:a", NOW).unwrap();
        assert_eq!(t.purge_expired(NOW).unwrap(), 0, "窗口内不该被清");
        assert_eq!(t.purge_expired(NOW + 1_000).unwrap(), 1);
        assert_eq!(
            t.check("ip:a", NOW + 1_000),
            ThrottleDecision::Allow { remaining: 5 }
        );
    }
}
