// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 限流 / 封禁闸门的公开 API 行为测试。
//!
//! 只走 `Throttle` 的公开方法，store 内部细节（Vec 有界、锁中毒恢复）在
//! `src/throttle/store.rs` 的单测里。

use security_rust::session::StoreError;
use security_rust::throttle::{
    MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome, ThrottleStore,
};

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

/// 全部方法都故障的后端 —— 用来证明 `check` 不 fail-closed。
#[derive(Debug)]
struct BrokenThrottleStore;

impl ThrottleStore for BrokenThrottleStore {
    fn record_failure(&self, _k: &str, _now: u64, _w: u64) -> Result<u32, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn failure_count(&self, _k: &str, _now: u64, _w: u64) -> Result<u32, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn is_banned(&self, _k: &str, _now: u64) -> Result<Option<u64>, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn ban(&self, _k: &str, _until: u64) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn clear_failures(&self, _k: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn reset(&self, _k: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn purge_expired(&self, _now: u64) -> Result<usize, StoreError> {
        Err(StoreError::Unavailable)
    }
}

/// 读路径可注入的后端：`banned` **原样返回**（不替 `check` 过滤），`count` 可设成故障。
#[derive(Debug)]
struct ReadFaultyStore {
    banned: Option<u64>,
    count: Result<u32, StoreError>,
}

impl ThrottleStore for ReadFaultyStore {
    fn record_failure(&self, _k: &str, _now: u64, _w: u64) -> Result<u32, StoreError> {
        Err(StoreError::Unavailable)
    }
    fn failure_count(&self, _k: &str, _now: u64, _w: u64) -> Result<u32, StoreError> {
        self.count.clone()
    }
    fn is_banned(&self, _k: &str, _now: u64) -> Result<Option<u64>, StoreError> {
        Ok(self.banned)
    }
    fn ban(&self, _k: &str, _until: u64) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn clear_failures(&self, _k: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn reset(&self, _k: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn purge_expired(&self, _now: u64) -> Result<usize, StoreError> {
        Err(StoreError::Unavailable)
    }
}

/// 计数正常、只有写封禁故障的后端 —— 钉住「封禁没写进去」的降级形态。
#[derive(Debug)]
struct BanWriteFailsStore(MemoryThrottleStore);

impl ThrottleStore for BanWriteFailsStore {
    fn record_failure(&self, k: &str, now: u64, w: u64) -> Result<u32, StoreError> {
        self.0.record_failure(k, now, w)
    }
    fn failure_count(&self, k: &str, now: u64, w: u64) -> Result<u32, StoreError> {
        self.0.failure_count(k, now, w)
    }
    fn is_banned(&self, k: &str, now: u64) -> Result<Option<u64>, StoreError> {
        self.0.is_banned(k, now)
    }
    fn ban(&self, _k: &str, _until: u64) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
    fn clear_failures(&self, k: &str) -> Result<(), StoreError> {
        self.0.clear_failures(k)
    }
    fn reset(&self, k: &str) -> Result<(), StoreError> {
        self.0.reset(k)
    }
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.0.purge_expired(now)
    }
}

// ── 封禁路径 ──────────────────────────────────────────────────────────

#[test]
fn threshold_failures_ban_on_the_last_one() {
    let t = throttle(3, 60, 900);
    assert_eq!(
        t.record_failure("ip:1.2.3.4", NOW).unwrap(),
        ThrottleOutcome::Allow { remaining: 2 }
    );
    assert_eq!(
        t.record_failure("ip:1.2.3.4", NOW + 1).unwrap(),
        ThrottleOutcome::Allow { remaining: 1 }
    );
    // 第 threshold 次失败即封禁：返回 Banned 而不是 Allow { remaining: 0 }
    assert_eq!(
        t.record_failure("ip:1.2.3.4", NOW + 2).unwrap(),
        ThrottleOutcome::Banned {
            until: NOW + 2 + 900
        }
    );
}

#[test]
fn check_is_banned_while_ban_lasts() {
    let t = throttle(1, 60, 900);
    t.record_failure("acct:u1", NOW).unwrap();
    assert_eq!(
        t.check("acct:u1", NOW),
        ThrottleDecision::Banned { until: NOW + 900 }
    );
    assert_eq!(
        t.check("acct:u1", NOW + 899),
        ThrottleDecision::Banned { until: NOW + 900 },
        "封禁期内每一请求都应被拒"
    );
}

#[test]
fn ban_lifts_at_until() {
    let t = throttle(1, 60, 900);
    t.record_failure("acct:u1", NOW).unwrap();
    // until 是解封时刻：到点即放行（此时失败也已滑出 60 秒窗口，额度回满）
    assert_eq!(
        t.check("acct:u1", NOW + 900),
        ThrottleDecision::Allow { remaining: 1 }
    );
}

#[test]
fn further_failures_after_ban_extend_nothing_but_stay_banned() {
    let t = throttle(1, 60, 900);
    t.record_failure("ip:a", NOW).unwrap();
    let again = t.record_failure("ip:a", NOW + 10).unwrap();
    assert_eq!(
        again,
        ThrottleOutcome::Banned {
            until: NOW + 10 + 900
        },
        "封禁中继续失败按新时刻续封"
    );
    assert_eq!(
        t.check("ip:a", NOW + 20),
        ThrottleDecision::Banned {
            until: NOW + 10 + 900
        }
    );
}

// ── 滑动窗口 ──────────────────────────────────────────────────────────

#[test]
fn failures_outside_the_window_do_not_count() {
    let t = throttle(3, 60, 900);
    assert_eq!(
        t.record_failure("acct:u1", NOW).unwrap(),
        ThrottleOutcome::Allow { remaining: 2 }
    );
    // 恰好 60 秒后：上一条正好滑出（保留条件是 t > now - window），计数仍为 1
    assert_eq!(
        t.record_failure("acct:u1", NOW + 60).unwrap(),
        ThrottleOutcome::Allow { remaining: 2 },
        "窗口外的失败必须滑出"
    );
    // 窗口内再失败一次则正常累计
    assert_eq!(
        t.record_failure("acct:u1", NOW + 90).unwrap(),
        ThrottleOutcome::Allow { remaining: 1 }
    );
    // 第三次仍落在 NOW+60 那条的 60 秒窗口内（119 - 60 = 59 < 60）⇒ 累计到 3，封禁
    assert_eq!(
        t.record_failure("acct:u1", NOW + 119).unwrap(),
        ThrottleOutcome::Banned {
            until: NOW + 119 + 900
        }
    );
}

#[test]
fn slow_bruteforce_never_trips_the_threshold() {
    // 每 61 秒失败一次：窗口内永远只有 1 条，不该被封
    let t = throttle(5, 60, 900);
    for i in 0..20 {
        let d = t.record_failure("acct:slow", NOW + i * 61).unwrap();
        assert!(
            matches!(d, ThrottleOutcome::Allow { .. }),
            "第 {i} 次不该封禁，got {d:?}"
        );
    }
}

// ── 成功清零 ──────────────────────────────────────────────────────────

#[test]
fn success_clears_failures_but_keeps_the_ban() {
    // threshold = 2、ban_secs = 30（< window）：封禁到期时那次失败仍在窗口内，
    // 于是「计数是否真被清掉」可观测 —— 没清的话 remaining 会是 0。
    let t = throttle(2, 60, 30);
    t.record_failure("ip:nat", NOW).unwrap();
    assert_eq!(
        t.record_failure("ip:nat", NOW).unwrap(),
        ThrottleOutcome::Banned { until: NOW + 30 }
    );
    // 共享桶（NAT 后面的另一个人）认证成功：计数归零，封禁照旧
    t.record_success("ip:nat").unwrap();
    assert_eq!(
        t.check("ip:nat", NOW + 1),
        ThrottleDecision::Banned { until: NOW + 30 },
        "认证成功只清计数，不能替桶里的其他人解除封禁"
    );
    assert_eq!(
        t.check("ip:nat", NOW + 31),
        ThrottleDecision::Allow { remaining: 2 },
        "封禁自然到期后计数确实已归零（不是被一起洗白）"
    );
}

#[test]
fn success_on_unknown_key_is_ok() {
    let t = throttle(5, 60, 900);
    assert!(t.record_success("ghost").is_ok());
}

#[test]
fn reset_clears_state_too() {
    let t = throttle(1, 60, 900);
    t.record_failure("ip:a", NOW).unwrap();
    t.reset("ip:a").unwrap();
    assert_eq!(
        t.check("ip:a", NOW),
        ThrottleDecision::Allow { remaining: 1 },
        "人工解封应立刻生效"
    );
}

// ── 不同 key 互不影响 ─────────────────────────────────────────────────

#[test]
fn keys_are_independent() {
    let t = throttle(2, 60, 900);
    t.record_failure("ip:a", NOW).unwrap();
    t.record_failure("ip:b", NOW).unwrap();
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap(),
        ThrottleOutcome::Banned { until: NOW + 900 }
    );
    assert_eq!(
        t.check("ip:b", NOW),
        ThrottleDecision::Allow { remaining: 1 },
        "ip:a 被封不影响 ip:b"
    );
    // 同一 IP 的 ip: / acct: 两个桶也互不干扰
    assert_eq!(
        t.check("acct:a", NOW),
        ThrottleDecision::Allow { remaining: 2 }
    );
}

// ── check 的 fail-closed 例外 ─────────────────────────────────────────

#[test]
fn check_is_unavailable_not_banned_when_store_fails() {
    let t = Throttle::new(BrokenThrottleStore, ThrottleConfig::default());
    // 有意不 fail-closed：后端抖动时把全体用户挡在门外是自我 DoS（且攻击者
    // 可能主动诱发），而放行只是暂时失去暴力破解防护 —— 主认证闸门
    // （SessionGuard）仍在拦。返回 Banned 才是错的。
    assert_eq!(
        t.check("ip:1.2.3.4", NOW),
        ThrottleDecision::Unavailable,
        "后端故障必须暴露为 Unavailable，而不是 Banned"
    );
    assert_ne!(
        t.check("ip:1.2.3.4", NOW),
        ThrottleDecision::Banned { until: 0 }
    );
}

#[test]
fn check_is_unavailable_when_the_count_query_fails_alone() {
    // 查封禁成功（未封禁）但取计数故障：`check` 内层的 Err 分支，
    // BrokenThrottleStore 只走到外层，这条路径此前没人踩过
    let t = Throttle::new(
        ReadFaultyStore {
            banned: None,
            count: Err(StoreError::Unavailable),
        },
        ThrottleConfig::default(),
    );
    assert_eq!(
        t.check("ip:1.2.3.4", NOW),
        ThrottleDecision::Unavailable,
        "计数查不到时同样不能替调用方做决定"
    );
}

#[test]
fn ban_write_failure_leaves_the_key_at_zero_budget() {
    // 已知降级（不是漏洞，但必须显式钉住）：计数已落库、封禁写失败 ⇒
    // 返回 Err，下次 check 放行但 remaining == 0。调用方据 remaining 拒绝即可；
    // 若这里返回 Unavailable 或 optimistic 的满额，反而会把状态说错。
    let t = Throttle::new(
        BanWriteFailsStore(MemoryThrottleStore::new()),
        ThrottleConfig {
            threshold: 2,
            window_secs: 60,
            ban_secs: 900,
        },
    );
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap(),
        ThrottleOutcome::Allow { remaining: 1 }
    );
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap_err(),
        StoreError::Unavailable,
        "封禁写失败要报给调用方"
    );
    assert_eq!(
        t.check("ip:a", NOW),
        ThrottleDecision::Allow { remaining: 0 },
        "封禁没写进去，但计数已到阈值"
    );
}

#[test]
fn check_does_not_trust_the_store_to_filter_expired_bans() {
    // 后端原样返回 banned_until：直到点 `check` 必须自行判定为已解封，
    // 否则一个过期的封禁会把 key 永久锁死（fail-closed，但仍是锁死）。
    let t = Throttle::new(
        ReadFaultyStore {
            banned: Some(NOW),
            count: Ok(0),
        },
        ThrottleConfig::default(),
    );
    assert_eq!(
        t.check("ip:a", NOW),
        ThrottleDecision::Allow { remaining: 5 },
        "until <= now 视为已解封"
    );
    assert_eq!(
        t.check("ip:a", NOW - 1),
        ThrottleDecision::Banned { until: NOW },
        "未到点仍要拦"
    );
}

#[test]
fn write_paths_propagate_store_errors() {
    let t = Throttle::new(BrokenThrottleStore, ThrottleConfig::default());
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap_err(),
        StoreError::Unavailable,
        "写路径仍要把故障报给调用方"
    );
    assert!(t.record_success("ip:a").is_err());
    assert!(t.reset("ip:a").is_err());
    assert!(t.purge_expired(NOW).is_err());
}

// ── 边界 ──────────────────────────────────────────────────────────────

#[test]
fn threshold_one_bans_on_first_failure() {
    let t = throttle(1, 60, 900);
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap(),
        ThrottleOutcome::Banned { until: NOW + 900 }
    );
    assert_eq!(
        t.check("ip:a", NOW),
        ThrottleDecision::Banned { until: NOW + 900 }
    );
}

#[test]
fn zero_ban_secs_unbans_immediately() {
    let t = throttle(1, 60, 0);
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap(),
        ThrottleOutcome::Banned { until: NOW },
        "ban_secs = 0 时解封时刻就是当下"
    );
    assert_eq!(
        t.check("ip:a", NOW),
        ThrottleDecision::Allow { remaining: 0 },
        "已解封，但窗口内额度确实用尽了（remaining 为 0）"
    );
}

#[test]
fn threshold_zero_bans_on_first_failure() {
    // threshold = 0 是「不给宽限」的配置，不该出现算术下溢
    let t = throttle(0, 60, 900);
    assert_eq!(
        t.record_failure("ip:a", NOW).unwrap(),
        ThrottleOutcome::Banned { until: NOW + 900 }
    );
}

#[test]
fn fresh_key_remaining_equals_threshold() {
    let t = throttle(7, 60, 900);
    assert_eq!(
        t.check("ip:never-seen", NOW),
        ThrottleDecision::Allow { remaining: 7 },
        "窗口为空时 remaining == threshold"
    );
}

#[test]
fn expired_ban_with_failures_still_in_window_reports_zero_remaining() {
    // threshold = 1 且 ban_secs = 0：解封后窗口内仍留着那次失败 ⇒ 额度钳到 0
    let t = throttle(1, 60, 0);
    t.record_failure("ip:a", NOW).unwrap();
    assert_eq!(
        t.check("ip:a", NOW + 1),
        ThrottleDecision::Allow { remaining: 0 },
        "剩余额度要钳在 0，不能下溢"
    );
}

// ── 空 key ────────────────────────────────────────────────────────────

#[test]
fn empty_key_behaves_like_any_other_key() {
    // 空 key 不做特殊处理，也不 panic；构造非空且不重名的 key 是调用方的责任
    let t = throttle(2, 60, 900);
    assert_eq!(t.check("", NOW), ThrottleDecision::Allow { remaining: 2 });
    assert_eq!(
        t.record_failure("", NOW).unwrap(),
        ThrottleOutcome::Allow { remaining: 1 }
    );
    assert_eq!(
        t.record_failure("", NOW).unwrap(),
        ThrottleOutcome::Banned { until: NOW + 900 }
    );
    assert_eq!(
        t.check("ip:a", NOW),
        ThrottleDecision::Allow { remaining: 2 },
        "空 key 是独立的一个桶"
    );
}

// ── 与主认证闸门配合 ──────────────────────────────────────────────────

#[test]
fn config_default_is_a_sane_starting_point() {
    let t = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
    assert_eq!(t.config().threshold, 5, "got {:?}", t.config());
    assert_eq!(t.config().window_secs, 60, "got {:?}", t.config());
    assert_eq!(t.config().ban_secs, 900, "got {:?}", t.config());
}
