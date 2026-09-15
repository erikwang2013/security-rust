// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! [`Throttle::check_any`] 的多维度合并规则测试。
//!
//! 单 key 的 `check` / `record_failure` 行为在 `tests/throttle.rs`（那里已接近
//! 500 行上限，故新开一个文件）；这里只测合并严格度：`Banned` > `Unavailable` > `Allow`。

use security_rust::session::StoreError;
use security_rust::throttle::{
    MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleStore,
};

const NOW: u64 = 1_000_000;
const FAULTY: &str = "ip:down";

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

/// 按 key 故障：只有 `faulty` 那个 key 的读路径返回 `Unavailable`，其余转发给内存 store。
/// 用来构造「一个维度健康、另一个维度后端挂了」的混合场景。
struct FaultyKeyStore {
    inner: MemoryThrottleStore,
    faulty: &'static str,
}

impl ThrottleStore for FaultyKeyStore {
    fn record_failure(&self, k: &str, now: u64, w: u64) -> Result<u32, StoreError> {
        self.inner.record_failure(k, now, w)
    }
    fn failure_count(&self, k: &str, now: u64, w: u64) -> Result<u32, StoreError> {
        if k == self.faulty {
            Err(StoreError::Unavailable)
        } else {
            self.inner.failure_count(k, now, w)
        }
    }
    fn is_banned(&self, k: &str, now: u64) -> Result<Option<u64>, StoreError> {
        if k == self.faulty {
            Err(StoreError::Unavailable)
        } else {
            self.inner.is_banned(k, now)
        }
    }
    fn ban(&self, k: &str, until: u64) -> Result<(), StoreError> {
        self.inner.ban(k, until)
    }
    fn clear_failures(&self, k: &str) -> Result<(), StoreError> {
        self.inner.clear_failures(k)
    }
    fn reset(&self, k: &str) -> Result<(), StoreError> {
        self.inner.reset(k)
    }
    fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.inner.purge_expired(now)
    }
}

fn faulty_throttle(threshold: u32, ban_secs: u64) -> Throttle<FaultyKeyStore> {
    Throttle::new(
        FaultyKeyStore {
            inner: MemoryThrottleStore::new(),
            faulty: FAULTY,
        },
        ThrottleConfig {
            threshold,
            window_secs: 60,
            ban_secs,
        },
    )
}

#[test]
fn check_any_takes_the_minimum_remaining() {
    let t = throttle(5, 60, 900);
    t.record_failure("ip:a", NOW).unwrap(); // 剩 4
    for _ in 0..3 {
        t.record_failure("acct:b", NOW).unwrap(); // 剩 2
    }
    assert_eq!(
        t.check_any(&["acct:b", "ip:a"], NOW),
        ThrottleDecision::Allow { remaining: 2 },
        "取最小的剩余额度，与 key 顺序无关"
    );
}

#[test]
fn check_any_banned_beats_allow_and_takes_the_latest_until() {
    let t = throttle(1, 60, 900);
    t.record_failure("ip:a", NOW).unwrap(); // 封到 NOW + 900
    t.record_failure("acct:b", NOW + 100).unwrap(); // 封到 NOW + 1000
    assert_eq!(
        t.check_any(&["ip:a", "acct:b", "ip:clean"], NOW + 200),
        ThrottleDecision::Banned { until: NOW + 1_000 },
        "任一被封即封；取最晚的解封时刻，没被封的维度不影响结论"
    );
}

#[test]
fn check_any_unavailable_beats_allow() {
    let t = faulty_throttle(5, 900);
    assert_eq!(
        t.check_any(&["ip:clean", FAULTY], NOW),
        ThrottleDecision::Unavailable,
        "一个维度健康、另一个后端故障 ⇒ 报 Unavailable，不能报那个乐观的 Allow"
    );
}

#[test]
fn check_any_banned_beats_unavailable() {
    let t = faulty_throttle(1, 900);
    t.record_failure("ip:evil", NOW).unwrap();
    assert_eq!(
        t.check_any(&[FAULTY, "ip:evil"], NOW),
        ThrottleDecision::Banned { until: NOW + 900 },
        "封禁是最严格的一档，压过后端故障"
    );
    // 封禁到期、窗口滑出后只剩故障这一档 —— key 顺序反过来也一样
    assert_eq!(
        t.check_any(&["ip:evil", FAULTY], NOW + 900),
        ThrottleDecision::Unavailable
    );
}

#[test]
fn check_any_empty_keys_reports_zero_budget() {
    let t = throttle(5, 60, 900);
    assert_eq!(
        t.check_any(&[], NOW),
        ThrottleDecision::Allow { remaining: 0 },
        "空 keys 一无所知，报 0 而不是凭空报满额"
    );
}

#[test]
fn check_any_single_key_matches_check() {
    let t = throttle(5, 60, 900);
    t.record_failure("ip:a", NOW).unwrap();
    assert_eq!(t.check_any(&["ip:a"], NOW), t.check("ip:a", NOW));
}
