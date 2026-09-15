// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! axum 接入模式参考 —— 把 [`SessionGuard`] 包成一层中间件。
//!
//! ```text
//! cargo run --example axum_middleware      # 自检，跑完即退出
//! cargo test  --example axum_middleware    # 同一个自检，走 #[tokio::test]
//! ```
//!
//! **这是接入模式，不是生产实现：**
//!
//! - store 用的是 [`MemoryStore`]（单进程内存），多实例部署要换成 Redis 版 store，
//!   否则负载均衡把请求打到另一台机器就会报 `TokenUnknown`。
//! - 时钟写死成常量，只为让自检可复现；真实部署用系统时钟（或 token 内嵌的 iat）。
//! - 这里只演示 `verify` 这一条路径。真实的登录端点还要调 `bind` / `rotate` /
//!   `revoke`，并配上 `Throttle` 记账 —— 见 `examples/waf.rs`。
//!
//! # 三个分支
//!
//! | `Decision`  | 处置                                        |
//! |-------------|---------------------------------------------|
//! | `Allow`     | 交给下游 handler                            |
//! | `Challenge` | 401 + `X-Step-Up-Auth: required`            |
//! | `Block`     | 401                                         |
//!
//! 中间件从请求头取 token / 指纹 / 位置来构造 [`RequestContext`]：
//! `X-Session-Token` / `X-Client-Fingerprint` / `X-Client-Region`。

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use security_rust::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};
use tower::ServiceExt;

/// 共享状态。`SessionGuard<S>` 只绑定 `SessionStore` trait，本身是 `Send + Sync`，
/// 用 `Arc` 包一层即可跨 handler / 任务共享。
type GuardState = Arc<SessionGuard<MemoryStore>>;

/// 自检用固定时钟 —— 真实部署换成 `SystemTime::now()` 的 unix 秒。
const NOW: u64 = 1_700_000_000;

const TOKEN_HEADER: &str = "x-session-token";
const FINGERPRINT_HEADER: &str = "x-client-fingerprint";
const REGION_HEADER: &str = "x-client-region";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    self_check().await
}

/// `cargo test --example axum_middleware` 跑的就是这一段。
#[tokio::test]
async fn middleware_branches_on_every_decision() {
    self_check().await.expect("自检失败");
}

/// 建 router、种一个会话、把三种 `Decision` 各走一遍并断言 HTTP 结果。
async fn self_check() -> Result<(), Box<dyn std::error::Error>> {
    let guard: GuardState = Arc::new(SessionGuard::new(
        MemoryStore::new(),
        SessionConfig::default(),
    ));
    let app = build_app(Arc::clone(&guard));

    // 种一个已登录的会话：alice @ CN-BJ，指纹 ip=10.0.0.1|ua=Firefox/128
    let login = RequestContext {
        token: "tok-alice-1",
        subject: "alice",
        fingerprint: "ip=10.0.0.1|ua=Firefox/128",
        location: Some("CN-BJ"),
        coords: None,
        signature: None,
        at: Some(NOW),
    };
    guard.bind(&login, NOW)?;

    println!("security-rust · axum 中间件接入示例");
    println!("已种会话：alice @ CN-BJ · tok-alice-1\n");

    // (标签, token, 指纹, 区域, 期望的中间件行为)
    let cases = [
        (
            "ALLOW      正常会话",
            "tok-alice-1",
            "ip=10.0.0.1|ua=Firefox/128",
            "CN-BJ",
            Expect::Pass,
        ),
        (
            "CHALLENGE  异地（位置变了，指纹没变）",
            "tok-alice-1",
            "ip=10.0.0.1|ua=Firefox/128",
            "US-NY",
            Expect::StepUp,
        ),
        (
            "BLOCK      指纹不符（token 被盗）",
            "tok-alice-1",
            "ip=203.0.113.9|ua=curl/8",
            "CN-BJ",
            Expect::Reject,
        ),
        (
            "BLOCK      未知 token",
            "tok-forged",
            "ip=10.0.0.1|ua=Firefox/128",
            "CN-BJ",
            Expect::Reject,
        ),
    ];

    for (label, token, fp, region, expect) in cases {
        let (status, step_up) = probe(app.clone(), token, fp, region).await?;
        let seen = match (status, step_up) {
            (StatusCode::OK, _) => Expect::Pass,
            (_, true) => Expect::StepUp,
            _ => Expect::Reject,
        };
        // 不补宽度：中文是双宽字符，按 `char` 数补齐反而对不齐
        println!(
            "  {label} → {status}{}",
            match step_up {
                true => " · X-Step-Up-Auth: required",
                false => "",
            }
        );
        assert_eq!(seen, expect, "{label}");
    }

    println!("\n三种 Decision 分支均按预期工作。");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Pass,
    StepUp,
    Reject,
}

/// 用 `oneshot` 把一条请求直接喂给 router，不起真实端口。
async fn probe(
    app: Router,
    token: &str,
    fingerprint: &str,
    region: &str,
) -> Result<(StatusCode, bool), Box<dyn std::error::Error>> {
    let req = Request::builder()
        .uri("/protected")
        .header(TOKEN_HEADER, token)
        .header(FINGERPRINT_HEADER, fingerprint)
        .header(REGION_HEADER, region)
        .body(axum::body::Body::empty())?;

    let res = app.oneshot(req).await?;
    let step_up = res.headers().get("x-step-up-auth").is_some();
    Ok((res.status(), step_up))
}

fn build_app(guard: GuardState) -> Router {
    Router::new()
        .route("/protected", get(protected))
        .layer(middleware::from_fn_with_state(guard, session_gate))
}

/// 下游业务 handler —— 只有过了中间件才会被调用。
async fn protected() -> &'static str {
    "ok"
}

/// 会话闸门。
///
/// 从请求头取三个字段构造 [`RequestContext`] 再调 [`SessionGuard::verify`]。
/// `subject` 在 `verify` 里不参与判定（异地历史按服务端记录的 subject 聚合），
/// 这里留空；`bind` 时它是必填的。
async fn session_gate(State(guard): State<GuardState>, req: Request, next: Next) -> Response {
    // 借用 req 的 header 构造 ctx，算完 decision 就把借用放掉，才能把 req 交给下游。
    let decision = {
        let headers = req.headers();
        let ctx = RequestContext {
            token: headers
                .get(TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            subject: "",
            fingerprint: headers
                .get(FINGERPRINT_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            location: headers.get(REGION_HEADER).and_then(|v| v.to_str().ok()),
            // 指纹里已含 IP，示例不再单独解析；生产环境可用已有 geo 库回填坐标，
            // 才能启用「不可能旅行」判定。
            coords: None,
            signature: None,
            at: Some(NOW),
        };
        guard.verify(&ctx, NOW).decision
    };

    match decision {
        Decision::Allow => next.run(req).await,
        Decision::Challenge => {
            let mut res = (StatusCode::UNAUTHORIZED, "step-up required").into_response();
            res.headers_mut()
                .insert("x-step-up-auth", HeaderValue::from_static("required"));
            res
        }
        Decision::Block => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Session")],
            "session rejected",
        )
            .into_response(),
    }
}
