// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::store::ThrottleStore;
use super::{StoreError, ThrottleConfig, ThrottleDecision};

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
            Ok(Some(until)) => ThrottleDecision::Banned { until },
            Ok(None) => match self
                .store
                .failure_count(key, now, self.config.window_secs)
            {
                Ok(count) => ThrottleDecision::Allow {
                    remaining: self.remaining(count),
                },
                Err(_) => ThrottleDecision::Unavailable,
            },
            Err(_) => ThrottleDecision::Unavailable,
        }
    }

    /// 认证失败时调用。达到 threshold 就封禁并返回 `Banned`，否则返回 `Allow { remaining }`。
    ///
    /// 判定顺序：先拿窗口内计数，`count >= threshold` 时写封禁并返回解封时刻。
    /// `threshold` 是「第几次失败触发封禁」，因此第 `threshold` 次调用返回的是
    /// `Banned` 而不是 `Allow { remaining: 0 }` —— 剩余额度为 0 的那次已经是拒绝。
    pub fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleDecision, StoreError> {
        let count = self.store.record_failure(key, now, self.config.window_secs)?;
        if count >= self.config.threshold {
            let until = now.saturating_add(self.config.ban_secs);
            self.store.ban(key, until)?;
            return Ok(ThrottleDecision::Banned { until });
        }
        Ok(ThrottleDecision::Allow {
            remaining: self.remaining(count),
        })
    }

    /// 认证成功时调用，清零计数。**同时清掉封禁**（凭据正确说明不是暴力破解）。
    pub fn record_success(&self, key: &str) -> Result<(), StoreError> {
        self.store.reset(key)
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
            assert_eq!(t.check("ip:a", NOW), ThrottleDecision::Allow { remaining: 5 });
        }
        assert_eq!(
            t.record_failure("ip:a", NOW).unwrap(),
            ThrottleDecision::Allow { remaining: 4 },
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
        assert_eq!(t.check("ip:a", NOW + 1_000), ThrottleDecision::Allow { remaining: 5 });
    }
}
