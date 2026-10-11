// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::StoreError;
use std::collections::HashMap;
use std::sync::Mutex;

/// 限流状态后端。
///
/// 所有 `now` 均为 unix 秒，调用方须保证**单调不减**（系统时钟正常满足）：
/// 滑动窗口靠比较时间戳，时间倒流会让新记录被当成过期数据丢掉。
pub trait ThrottleStore: Send + Sync {
    /// 记录一次失败，返回**窗口内**的累计失败数（含本次）。
    /// 实现须自行滑动窗口：只计 `now - window_secs` 之后的失败。
    fn record_failure(&self, key: &str, now: u64, window_secs: u64) -> Result<u32, StoreError>;
    /// 只读查询窗口内失败数，**不写入任何状态**。
    ///
    /// 供 `Throttle::check` 在放行时算剩余额度 —— 没有它，请求路径只能返回一个
    /// 乐观的满额数字（`remaining` 会被写进 X-RateLimit 响应头，谎报等于误导调用方）。
    fn failure_count(&self, key: &str, now: u64, window_secs: u64) -> Result<u32, StoreError>;
    /// 该 key 是否处于封禁中；是则返回解封时刻。
    ///
    /// 返回**未过滤的原始值也是合法的**：`Throttle::check` 会自己拿 `now` 比对
    /// `until` 再决定是否 `Banned`，后端不必代劳（返回 `Some(until)` 且
    /// `until <= now` 不会被当成永久封禁）。
    fn is_banned(&self, key: &str, now: u64) -> Result<Option<u64>, StoreError>;
    /// 写入封禁截止时刻。**只能延长不能缩短**：已生效的封禁遇上更早的 `until`
    /// 应被忽略（时钟回拨时 `now + ban_secs` 可能反而更小）。
    fn ban(&self, key: &str, until: u64) -> Result<(), StoreError>;
    /// 只清空失败计数，**保留封禁**。
    ///
    /// 认证成功走这里，人工解封走 `reset`：二者合并会让共享桶（如 `ip:`）的封禁
    /// 被桶里任意另一个人一次成功认证解除。
    fn clear_failures(&self, key: &str) -> Result<(), StoreError>;
    /// 清零该 key 的失败计数与封禁。
    fn reset(&self, key: &str) -> Result<(), StoreError>;
    /// 清除已过期状态，返回清除条数。
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError>;
}

/// 某个 key 的限流状态。
///
/// 存**时间戳**而非计数：只有留下每次失败的坐标才能滑动窗口 ——
/// 单纯自增的计数器没法判断「哪几次失败已经滑出窗口」，只能整段清零。
#[derive(Debug, Default)]
struct Entry {
    /// 窗口内的失败时刻。时钟单调时才恰好是非递减的，回拨会破坏这个序 ——
    /// 因此判定一律扫全量，不要用 `last()`。
    failures: Vec<u64>,
    /// 封禁截止时刻；`None` 表示从未封禁。只增不减：`ban` 取 max，时钟回拨
    /// 不会把已生效的封禁缩短。
    banned_until: Option<u64>,
    /// 最近一次 `record_failure` 传入的窗口长度，仅供 `purge_expired` 判断陈旧。
    /// store 不记住窗口，就无法区分「窗口内仍有效的失败」与「早该滑出的失败」，
    /// 而 `purge_expired(now)` 的签名里没有窗口参数。
    window_secs: u64,
}

/// 单个 key 的 [`Entry::failures`] 向量上限。
///
/// 为什么需要硬上限：`retain` 的代价是 O(保留条数)，而保留条数取决于调用方传入的
/// `now`。时钟冻结（或倒退）时没有任何失败会滑出窗口，向量随调用次数无上限增长
/// —— 性能评审实测每次调用 2.5 万条 6.7µs、10 万条 52.9µs，且随条数线性恶化，
/// 内存同理。有上限后单 key 的每次调用与占用都是常数级。
///
/// 上限为什么安全：封禁判定只看 `count >= threshold`，计数越过阈值后再涨没有区分度，
/// 在饱和值停住即可 —— 于是**阈值 ≤ 本值的配置判定逐字不变**（默认 5，远在范围内），
/// 只有把 threshold 配到 1024 以上的调用方才会观察到计数封顶、永不触发封禁。
const MAX_TRACKED_FAILURES: usize = 1024;

/// 内存后端。无后台线程，且**只有写路径**会清理：`record_failure` 顺手
/// `retain` 掉滑出窗口的失败，`failure_count` / `is_banned` 这类读路径不碰状态。
///
/// 于是有两条边界：
/// - 每个 key 的 `failures` 向量有界：每次 `record_failure` 都 retain，上界是
///   `min(窗口内失败数, MAX_TRACKED_FAILURES)` —— 前者挡正常增长，后者挡时钟
///   冻结/回拨、窗口整个失效时的无界增长；
/// - **map 本身的条目数无上限** —— key 只增不减，只有 `purge_expired`（和
///   `reset`）会移除条目。
///
/// 长期运行的进程必须按定时器调 `purge_expired`（间隔取 `window_secs` 量级即可），
/// 否则 key 基数的增长会一直吃内存。
#[derive(Debug)]
pub struct MemoryThrottleStore {
    entries: Mutex<HashMap<String, Entry>>,
}

impl Default for MemoryThrottleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryThrottleStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 互斥锁获取。线程 panic 导致锁中毒时恢复内部数据而非永久 Err：
    /// 本 store 的每个操作都是单次 HashMap 读/写（外加一次与本次读写同批完成的
    /// `Vec::retain`），不存在「改到一半」的不变量，恢复是安全的；
    /// 而让一次 panic 永久锁死整个限流存储是一种自我 DoS。
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 窗口下界：早于或等于它的失败都算滑出。
    fn cutoff(now: u64, window_secs: u64) -> u64 {
        now.saturating_sub(window_secs)
    }
}

impl ThrottleStore for MemoryThrottleStore {
    fn record_failure(&self, key: &str, now: u64, window_secs: u64) -> Result<u32, StoreError> {
        let cutoff = Self::cutoff(now, window_secs);
        let mut g = Self::lock(&self.entries);
        let e = g.entry(key.to_string()).or_default();
        e.window_secs = window_secs;
        // ponytail: 每次失败做一次 O(保留条数) 的 retain，不需要后台清理线程。
        // 天花板 = min(窗口内失败数, MAX_TRACKED_FAILURES)：默认配置（窗口 60s、
        // 每秒重试一次）约 60 条，单 key 几 KB。若 threshold 动到 1024 以上，
        // 改环形缓冲或分桶计数（bucket 粒度 = window/10 的固定格子）。
        e.failures.retain(|t| *t > cutoff);
        // 封顶：满了就不再 push，计数在饱和值停住，而不是让向量无限长。
        // 对阈值 ≤ 上限的配置，`count >= threshold` 的判定与不封顶时逐字相同
        // （见 MAX_TRACKED_FAILURES 的说明）。
        if e.failures.len() < MAX_TRACKED_FAILURES {
            e.failures.push(now);
        }
        Ok(e.failures.len() as u32)
    }

    fn failure_count(&self, key: &str, now: u64, window_secs: u64) -> Result<u32, StoreError> {
        let cutoff = Self::cutoff(now, window_secs);
        let g = Self::lock(&self.entries);
        Ok(g.get(key)
            .map(|e| e.failures.iter().filter(|t| **t > cutoff).count() as u32)
            .unwrap_or(0))
    }

    fn is_banned(&self, key: &str, now: u64) -> Result<Option<u64>, StoreError> {
        Ok(Self::lock(&self.entries)
            .get(key)
            .and_then(|e| e.banned_until)
            // `until` 是解封时刻：到点即解封，故严格大于
            .filter(|until| *until > now))
    }

    fn ban(&self, key: &str, until: u64) -> Result<(), StoreError> {
        let mut g = Self::lock(&self.entries);
        let e = g.entry(key.to_string()).or_default();
        // 取 max：时钟回拨后 `now + ban_secs` 可能早于已写入的 until，
        // 无条件覆盖等于让攻击者靠回拨提前解封。
        e.banned_until = Some(e.banned_until.map_or(until, |existing| existing.max(until)));
        Ok(())
    }

    fn clear_failures(&self, key: &str) -> Result<(), StoreError> {
        if let Some(e) = Self::lock(&self.entries).get_mut(key) {
            e.failures.clear();
        }
        Ok(())
    }

    fn reset(&self, key: &str) -> Result<(), StoreError> {
        Self::lock(&self.entries).remove(key);
        Ok(())
    }

    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        let mut g = Self::lock(&self.entries);
        let before = g.len();
        g.retain(|_, e| {
            // 封禁未到期 ⇒ 留着；否则只要窗口内还有失败也留着。
            // 两者都不成立才叫「过期」—— 只清封禁记录而不看失败，会把还在
            // 计数窗口内的对手顺手洗白，等于给攻击者一个免费的计数重置。
            let banned = e.banned_until.is_some_and(|until| until > now);
            // 扫全量而非取 `last()`：`failures` 只在时钟单调时才是非递减的，
            // 回拨会让 `last()` 变成最小值，把窗口内的有效失败整条丢掉。
            let fresh = e
                .failures
                .iter()
                .any(|t| *t > Self::cutoff(now, e.window_secs));
            banned || fresh
        });
        Ok(before - g.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::throttle::{Throttle, ThrottleConfig, ThrottleDecision};

    const NOW: u64 = 1_000_000;

    fn store() -> MemoryThrottleStore {
        MemoryThrottleStore::new()
    }

    #[test]
    fn record_failure_counts_within_window() {
        let s = store();
        assert_eq!(s.record_failure("k", NOW, 60).unwrap(), 1);
        assert_eq!(s.record_failure("k", NOW + 1, 60).unwrap(), 2);
    }

    #[test]
    fn failures_at_window_edge_are_dropped() {
        let s = store();
        s.record_failure("k", NOW, 60).unwrap();
        // 恰好 window_secs 秒前的失败算滑出（保留条件是 t > now - window）
        assert_eq!(s.record_failure("k", NOW + 60, 60).unwrap(), 1);
        // 窗口内一秒之差则仍计入
        assert_eq!(s.record_failure("k", NOW + 61, 60).unwrap(), 2);
    }

    #[test]
    fn failure_count_is_read_only() {
        let s = store();
        assert_eq!(s.failure_count("k", NOW, 60).unwrap(), 0);
        s.record_failure("k", NOW, 60).unwrap();
        assert_eq!(s.failure_count("k", NOW, 60).unwrap(), 1);
        // 查十次也不该把计数查大
        for _ in 0..10 {
            assert_eq!(s.failure_count("k", NOW, 60).unwrap(), 1);
        }
        assert_eq!(s.record_failure("k", NOW, 60).unwrap(), 2);
    }

    #[test]
    fn failure_count_of_unknown_key_is_zero() {
        let s = store();
        assert_eq!(s.failure_count("ghost", NOW, 60).unwrap(), 0);
    }

    #[test]
    fn failures_vec_stays_bounded_to_window() {
        // 有界性：窗口外的失败必须真被丢掉，否则 Vec 无上限增长
        let s = store();
        for i in 0..100 {
            s.record_failure("k", NOW + i, 60).unwrap();
        }
        // 每秒一次、窗口 60 秒 ⇒ 至多留下 60 条，而不是 100 条
        assert_eq!(len(&s, "k"), 60, "窗口外的失败必须真被丢弃");
        // 跳到窗口之外再来一次，前面 60 条也应全部被清掉
        s.record_failure("k", NOW + 1_000, 60).unwrap();
        assert_eq!(len(&s, "k"), 1);
    }

    #[test]
    fn frozen_clock_growth_is_capped_and_threshold_verdict_unchanged() {
        // 时钟冻结 ⇒ 没有失败滑出窗口 ⇒ 只有硬上限挡得住无界增长
        let s = store();
        let mut count = 0;
        for _ in 0..(MAX_TRACKED_FAILURES + 100) {
            count = s.record_failure("k", NOW, 60).unwrap();
        }
        assert_eq!(len(&s, "k"), MAX_TRACKED_FAILURES, "failures 必须有硬上限");
        assert_eq!(count, MAX_TRACKED_FAILURES as u32, "计数在饱和值上停住");

        // 阈值 ≤ 上限时封禁判定不受影响：饱和计数照样越线，
        // Banned 与未封顶时完全相同（阈值 5 在第 5 次就封）
        let t = Throttle::new(
            MemoryThrottleStore::new(),
            ThrottleConfig {
                threshold: 5,
                window_secs: 60,
                ban_secs: 900,
            },
        );
        for _ in 0..(MAX_TRACKED_FAILURES + 100) {
            t.record_failure("k", NOW).unwrap();
        }
        assert_eq!(
            t.check("k", NOW),
            ThrottleDecision::Banned { until: NOW + 900 },
            "饱和不得改变封禁判定"
        );
    }

    #[test]
    fn banned_expires_at_until_exclusive() {
        let s = store();
        s.ban("k", NOW + 100).unwrap();
        assert_eq!(s.is_banned("k", NOW).unwrap(), Some(NOW + 100));
        assert_eq!(s.is_banned("k", NOW + 99).unwrap(), Some(NOW + 100));
        assert_eq!(s.is_banned("k", NOW + 100).unwrap(), None);
    }

    #[test]
    fn is_banned_unknown_key_is_none() {
        let s = store();
        assert_eq!(s.is_banned("ghost", NOW).unwrap(), None);
    }

    #[test]
    fn reset_clears_failures_and_ban() {
        let s = store();
        s.record_failure("k", NOW, 60).unwrap();
        s.ban("k", NOW + 100).unwrap();
        s.reset("k").unwrap();
        assert_eq!(s.failure_count("k", NOW, 60).unwrap(), 0);
        assert_eq!(s.is_banned("k", NOW).unwrap(), None);
    }

    #[test]
    fn reset_unknown_key_is_ok() {
        let s = store();
        assert!(s.reset("ghost").is_ok());
    }

    #[test]
    fn purge_keeps_banned_and_fresh_entries() {
        let s = store();
        s.record_failure("stale", NOW, 60).unwrap();
        s.record_failure("fresh", NOW + 990, 60).unwrap();
        s.ban("banned", NOW + 5_000).unwrap();
        assert_eq!(s.purge_expired(NOW + 1_000).unwrap(), 1);
        assert_eq!(s.failure_count("stale", NOW + 1_000, 60).unwrap(), 0);
        assert_eq!(s.failure_count("fresh", NOW + 1_000, 60).unwrap(), 1);
        assert!(s.is_banned("banned", NOW + 1_000).unwrap().is_some());
    }

    #[test]
    fn purge_with_expired_ban_drops_entry() {
        let s = store();
        s.record_failure("k", NOW, 60).unwrap();
        s.ban("k", NOW + 10).unwrap();
        // 封禁已到期且失败已滑出窗口 ⇒ 状态全过期
        assert_eq!(s.purge_expired(NOW + 100).unwrap(), 1);
        assert_eq!(s.is_banned("k", NOW + 100).unwrap(), None);
    }

    #[test]
    fn purge_empty_store_is_zero() {
        let s = store();
        assert_eq!(s.purge_expired(NOW).unwrap(), 0);
    }

    #[test]
    fn purge_keeps_in_window_failures_after_clock_rollback() {
        // 回拨让 failures 乱序成 [NOW, NOW-200]：取 `last()` 会拿到最小值，
        // 把仍在窗口内的 [NOW] 判成过期 —— 攻击者只要诱发一次回拨再等一次
        // purge，计数就被免费重置。判定必须扫全量。
        let s = store();
        s.record_failure("k", NOW, 60).unwrap();
        s.record_failure("k", NOW - 200, 60).unwrap();
        assert_eq!(s.failure_count("k", NOW, 60).unwrap(), 1);
        assert_eq!(
            s.purge_expired(NOW).unwrap(),
            0,
            "窗口内仍有有效失败，不该清"
        );
        assert_eq!(
            s.failure_count("k", NOW, 60).unwrap(),
            1,
            "计数不能被 purge 免费重置"
        );
    }

    #[test]
    fn ban_cannot_be_shortened_by_clock_rollback() {
        let s = store();
        s.ban("k", NOW + 900).unwrap();
        // 回拨后重新封禁：天真的 `until = now + ban_secs` 会写进一个更早的时刻
        s.ban("k", NOW - 5_000 + 900).unwrap();
        assert_eq!(
            s.is_banned("k", NOW).unwrap(),
            Some(NOW + 900),
            "封禁只能延长，回拨不能提前解封"
        );
    }

    #[test]
    fn empty_key_is_a_normal_key() {
        // 空 key 不做特殊处理：调用方负责构造非空且不重名的 key
        let s = store();
        assert_eq!(s.record_failure("", NOW, 60).unwrap(), 1);
        assert_eq!(s.record_failure("", NOW, 60).unwrap(), 2);
        assert_eq!(s.record_failure("k", NOW, 60).unwrap(), 1);
    }

    #[test]
    fn lock_recovers_from_poisoned_mutex() {
        // 钉住 lock() 的恢复不变量：一次 panic 不能永久锁死限流存储
        let m = Mutex::new(Entry {
            failures: vec![NOW],
            banned_until: Some(NOW + 1),
            window_secs: 60,
        });
        std::panic::catch_unwind(|| {
            let _guard = m.lock().unwrap();
            panic!("poison");
        })
        .unwrap_err();
        assert!(m.is_poisoned());

        let g = MemoryThrottleStore::lock(&m);
        assert_eq!(g.failures, vec![NOW]);
        assert_eq!(g.banned_until, Some(NOW + 1));
    }

    /// 直接读私有字段，只有单测能这么干。
    fn len(s: &MemoryThrottleStore, key: &str) -> usize {
        MemoryThrottleStore::lock(&s.entries)
            .get(key)
            .map(|e| e.failures.len())
            .unwrap_or(0)
    }
}
