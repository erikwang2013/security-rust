// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 端到端 WAF 链路示例 —— 把本 crate 的四个子系统串成一条请求流水线。
//!
//! ```text
//! cargo run --example waf
//! ```
//!
//! 单次请求的处置顺序：
//!
//! 1. [`Scanner::scan`] —— 32 个无状态检测器扫原始 payload
//! 2. [`Scanner::assess`] —— 命中聚合成 `RiskAssessment`，`>= High` 直接拒
//! 3. [`Throttle::check_any`] —— `ip:` / `acct:` 两个维度一次查完限流与封禁
//! 4. `record_failure` / `record_success` —— 认证结果记账
//! 5. [`SessionGuard::verify`] —— token / 指纹 / 位置绑定校验，按 `Decision` 三档处置
//!
//! 覆盖场景：正常请求放行、SQLi / XSS 被拒、异地登录 → Challenge、
//! 指纹不符 → Block（劫持）、连续认证失败 → 限流封禁、封禁到期自动恢复。
//!
//! 时间一律用固定递增常量，不用 `SystemTime::now()` —— 示例输出逐字节可复现。
//! 这是接入参考，不是生产实现：内存 store 换成 Redis 版 store 即可多实例部署。

use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, RequestContext, RiskAssessment, RiskLevel, Scanner,
    SessionConfig, SessionGuard, SessionVerdict, Throttle, ThrottleConfig, ThrottleDecision,
    ThrottleOutcome,
};

/// 固定时钟起点。递增的常量代替真实时钟，保证输出可复现。
const T0: u64 = 1_700_000_000;

/// alice 登录时绑定的客户端指纹。
const FP_ALICE: &str = "ip=10.0.0.1|ua=Firefox/128";

/// 流水线最终处置。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// 放行
    Allow,
    /// 放行但要求二次验证（step-up）
    StepUp,
    /// 拒绝，附原因
    Reject(String),
}

/// 一条待处理的请求。所有字段都是字面量，因此可以整表静态构造。
struct Request<'a> {
    /// 便于阅读输出
    title: &'a str,
    ip: &'a str,
    account: &'a str,
    payload: &'a str,
    /// 本次请求带的是密码认证时，密码是否正确。
    /// 会话复用（token）的正确性由第 5 步的 `verify` 负责，两者是独立的两件事。
    password_ok: bool,
    ctx: RequestContext<'a>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::new();
    let throttle = Throttle::new(
        MemoryThrottleStore::new(),
        ThrottleConfig {
            threshold: 5,
            window_secs: 60,
            ban_secs: 900,
        },
    );
    let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

    println!("security-rust · 端到端 WAF 链路示例");
    println!("固定时钟 T0={T0}；限流 5 次失败 / 60s 窗口 → 封禁 900s");

    // ── 登录：建会话 + 绑指纹 + 记登录位置 ──────────────────────────────
    let login = RequestContext {
        token: "tok-alice-1",
        subject: "alice",
        fingerprint: FP_ALICE,
        location: Some("CN-BJ"),
        coords: Some((39.9042, 116.4074)),
        signature: None,
        at: Some(T0),
    };
    // `bind` 返回 Result 而非 verdict —— 调用方误用（空 token/subject/指纹）
    // 与后端故障都要显式处理，`?` 把两者交给 main 的错误返回。
    let verdict = guard.bind(&login, T0)?;
    println!(
        "\nlogin    : alice @ CN-BJ · token=tok-alice-1\n           {}{}",
        describe(&verdict),
        if verdict.is_allowed() {
            "（异地只影响 verdict，不阻断登录）"
        } else {
            ""
        }
    );

    // ── 逐条跑流水线 ─────────────────────────────────────────────────
    let mut allowed = 0usize;
    let mut step_ups = 0usize;
    let mut rejected = 0usize;

    for req in requests().iter() {
        match handle(req, &scanner, &throttle, &guard, req.ctx.at.unwrap_or(T0)) {
            Action::Allow => {
                allowed += 1;
                println!("  verdict  : ✅ 放行");
            }
            Action::StepUp => {
                step_ups += 1;
                println!("  verdict  : ⚠️  二次验证（step-up），带外确认后再放行");
            }
            Action::Reject(reason) => {
                rejected += 1;
                println!("  verdict  : ⛔ 拒绝 —— {reason}");
            }
        }
    }

    // ── 封禁到期：check 自己拿 now 比对 until，不需要任何清理动作 ────────
    let after_ban = T0 + 1_000;
    println!("\n── 封禁到期观察 ── t={after_ban}");
    match throttle.check("ip:203.0.113.7", after_ban) {
        ThrottleDecision::Allow { remaining } => println!(
            "  throttle : 封禁已自动到期（now >= until），剩余额度 {remaining} —— 无需人工解封"
        ),
        other => println!("  throttle : {other:?}"),
    }

    // ── 定期清理：MemoryThrottleStore 的 key 只增不减，只有 purge_expired
    // （和 reset）会移除条目。长期运行的进程必须按定时器调它（间隔取
    // window_secs 量级即可），否则 key 基数增长会一直吃内存。
    let purged = throttle.purge_expired(after_ban)?;
    println!("  throttle : purge_expired 清掉 {purged} 条已过期状态");

    println!("\n汇总：放行 {allowed} · 二次验证 {step_ups} · 拒绝 {rejected}");
    Ok(())
}

/// 走完整条流水线，返回最终处置。
fn handle(
    req: &Request<'_>,
    scanner: &Scanner,
    throttle: &Throttle<MemoryThrottleStore>,
    guard: &SessionGuard<MemoryStore>,
    now: u64,
) -> Action {
    println!("\n── {} ── t={now}", req.title);

    // ── 1) 字符串层：32 个无状态检测器 ────────────────────────────────
    let hits = scanner.scan(req.payload);
    if hits.is_empty() {
        println!("  scan     : 无命中");
    } else {
        for h in &hits {
            println!(
                "  scan     : [{}] {} · {} · offset={} · 命中 {:?}",
                h.category, h.attack_type, h.severity, h.offset, h.matched_pattern
            );
        }
    }

    // ── 2) 聚合成风险等级 ────────────────────────────────────────────
    let risk = scanner.assess(req.payload);
    println!("  risk     : {}", describe_risk(&risk));
    if risk.level >= RiskLevel::High {
        return Action::Reject(format!("payload risk {}", risk.level));
    }

    // ── 3) 限流闸门 ─────────────────────────────────────────────────
    // 两个维度（来源 IP + 目标账户）一次查完，合并规则由 `check_any` 定义：
    // 任一被封即封，否则取最严格的一档。调用方不再自己发明谁压谁。
    let ip_key = format!("ip:{}", req.ip);
    let acct_key = format!("acct:{}", req.account);
    match throttle.check_any(&[ip_key.as_str(), acct_key.as_str()], now) {
        ThrottleDecision::Banned { until } => {
            println!(
                "  throttle : BANNED · {ip_key} / {acct_key} · 解封于 {until}（还剩 {}s）",
                until.saturating_sub(now)
            );
            return Action::Reject("throttle: banned".into());
        }
        ThrottleDecision::Allow { remaining } => {
            println!("  throttle : allow · {ip_key} / {acct_key} · 剩余额度 {remaining}");
        }
        // 有意不 fail-closed：限流是纵深防御，后端抖动时挡下全体用户是自我 DoS，
        // 主认证闸门（下一步的 SessionGuard）仍然在拦。
        ThrottleDecision::Unavailable => {
            println!("  throttle : store 不可用 → 放行 + 告警（本模块有意不 fail-closed）");
        }
    }

    // ── 4) 认证结果记账 ──────────────────────────────────────────────
    if req.password_ok {
        for key in [&ip_key, &acct_key] {
            if let Err(e) = throttle.record_success(key) {
                println!("  auth     : record_success({key}) 失败: {e}");
            }
        }
        println!("  auth     : 密码正确 → 清空失败计数（注意：不清封禁）");
    } else {
        for key in [&ip_key, &acct_key] {
            // `record_failure` 返回 `Result<ThrottleOutcome, _>`：两个可达状态 + 一个错误，
            // 没有 `Unavailable` 那个永远走不到的分支。
            match throttle.record_failure(key, now) {
                Ok(ThrottleOutcome::Banned { until }) => {
                    println!("  auth     : 密码错误 · {key} 达到阈值 → 封禁至 {until}");
                }
                Ok(ThrottleOutcome::Allow { remaining }) => {
                    println!("  auth     : 密码错误 · {key} · 剩余额度 {remaining}");
                }
                Err(e) => println!("  auth     : 密码错误 · {key} · 记账失败: {e}"),
            }
        }
    }

    // ── 5) 会话校验 ─────────────────────────────────────────────────
    // `verify` 返回 verdict 而非 Result：认证路径上「拒绝」是正常结果不是错误，
    // 类型层面强制调用方处理每一种拒绝。
    let verdict = guard.verify(&req.ctx, now);
    println!("  session  : {}", describe(&verdict));

    match verdict.decision {
        Decision::Allow => Action::Allow,
        Decision::Challenge => Action::StepUp,
        Decision::Block => Action::Reject(format!("session: {}", threat_list(&verdict))),
    }
}

/// 示例脚本：固定时间、固定输入。
fn requests() -> Vec<Request<'static>> {
    let alice = |token: &'static str, fp: &'static str, loc: &'static str, at: u64| RequestContext {
        token,
        subject: "alice",
        fingerprint: fp,
        location: Some(loc),
        coords: None,
        signature: None,
        at: Some(at),
    };

    vec![
        Request {
            title: "REQ-1 正常请求",
            ip: "10.0.0.1",
            account: "alice",
            payload: "/products/running-shoes",
            password_ok: true,
            ctx: alice("tok-alice-1", FP_ALICE, "CN-BJ", T0 + 1),
        },
        Request {
            title: "REQ-2 SQL 注入",
            ip: "198.51.100.4",
            account: "alice",
            payload: "/search?q=' OR 1=1 --",
            password_ok: true,
            ctx: alice("tok-alice-1", FP_ALICE, "CN-BJ", T0 + 2),
        },
        Request {
            title: "REQ-3 XSS",
            ip: "198.51.100.5",
            account: "alice",
            payload: "/comment?body=<script>alert(document.cookie)</script>",
            password_ok: true,
            ctx: alice("tok-alice-1", FP_ALICE, "CN-BJ", T0 + 3),
        },
        Request {
            title: "REQ-4 异地登录（同指纹、同 token，位置变了）",
            ip: "10.0.0.1",
            account: "alice",
            payload: "/account",
            password_ok: true,
            ctx: alice("tok-alice-1", FP_ALICE, "US-NY", T0 + 4),
        },
        Request {
            title: "REQ-5 会话劫持（token 被盗，指纹不符）",
            ip: "203.0.113.9",
            account: "alice",
            payload: "/account",
            password_ok: true,
            ctx: alice("tok-alice-1", "ip=203.0.113.9|ua=curl/8", "CN-BJ", T0 + 5),
        },
        Request {
            title: "REQ-6a 暴力破解 · 第 1 次失败",
            ip: "203.0.113.7",
            account: "mallory",
            payload: "/login",
            password_ok: false,
            ctx: alice("tok-forged", FP_ALICE, "CN-BJ", T0 + 10),
        },
        Request {
            title: "REQ-6b 暴力破解 · 第 2 次失败",
            ip: "203.0.113.7",
            account: "mallory",
            payload: "/login",
            password_ok: false,
            ctx: alice("tok-forged", FP_ALICE, "CN-BJ", T0 + 11),
        },
        Request {
            title: "REQ-6c 暴力破解 · 第 3 次失败",
            ip: "203.0.113.7",
            account: "mallory",
            payload: "/login",
            password_ok: false,
            ctx: alice("tok-forged", FP_ALICE, "CN-BJ", T0 + 12),
        },
        Request {
            title: "REQ-6d 暴力破解 · 第 4 次失败",
            ip: "203.0.113.7",
            account: "mallory",
            payload: "/login",
            password_ok: false,
            ctx: alice("tok-forged", FP_ALICE, "CN-BJ", T0 + 13),
        },
        Request {
            title: "REQ-6e 暴力破解 · 第 5 次失败（达到阈值）",
            ip: "203.0.113.7",
            account: "mallory",
            payload: "/login",
            password_ok: false,
            ctx: alice("tok-forged", FP_ALICE, "CN-BJ", T0 + 14),
        },
        Request {
            title: "REQ-7 拿到正确密码也进不来（封禁未到期）",
            ip: "203.0.113.7",
            account: "mallory",
            payload: "/login",
            password_ok: true,
            ctx: alice("tok-forged", FP_ALICE, "CN-BJ", T0 + 15),
        },
    ]
}

fn threat_list(v: &SessionVerdict) -> String {
    if v.threats.is_empty() {
        return "无威胁".into();
    }
    v.threats
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `Decision` / `SessionThreat` 都实现了 `Display`，日志层直接打印，不必自备标签表。
///
/// `severity` 是 `Option`：放行时**没有** severity 字段可打。换成占位的 `LOW`，
/// 日志里就跟「发现一条低危」一模一样 —— 一条全放行的正常请求被读成有发现。
fn describe(v: &SessionVerdict) -> String {
    match &v.severity {
        None => format!("{} · threats=[{}]", v.decision, threat_list(v)),
        Some(severity) => format!(
            "{} · severity={severity} · threats=[{}]",
            v.decision,
            threat_list(v)
        ),
    }
}

fn describe_risk(r: &RiskAssessment) -> String {
    format!("level={} score={} results={}", r.level, r.score, r.results)
}
