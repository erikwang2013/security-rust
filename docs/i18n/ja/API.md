<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API リファレンス

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語 (本页)](./API.md)

---

## コア Trait

### `Detector`

全検出器の唯一の契約:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — 検出器名（例: `"xss"`、`"sql_injection"`）
- `detect()` — 入力をスキャンし、ヒット時は `Some(DetectionResult)` を、未ヒット時は `None` を返す

`session` と `throttle` は意図的にこの trait を実装していません（[セッションセキュリティ](#セッションセキュリティ-session) を参照）。両者は状態と識別情報を扱い、「token + フィンガープリント + 位置 + 時刻」という複合入力を単一の `&str` では表現できないためです。

## 検出結果の構造

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // マッチした具体的なパターン断片
    pub offset: usize,            // 入力内のバイトオフセット
    pub message: String,          // 人間が読める説明
}
```

## Scanner

### インストール

```toml
[dependencies]
security-rust = "1.0.8"
```

### クイックスタート

```rust
use security_rust::Scanner;

fn main() {
    // ゼロ設定: 全 32 個の検出器を装備
    let scanner = Scanner::default();

    // 入力をスキャンし、検出されたすべての攻撃を返す
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 出力:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### 選択的スキャン

```rust
let scanner = Scanner::default();

// 指定した検出器のみ実行
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### カスタム設定

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// builder で必要な検出器だけを装備
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 重大度表示

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## セッションセキュリティ (`session`)

クライアントによるセッション乗っ取り、データ改竄、不可能旅行（短時間での地理的移動）、token セッションの失効を判定します。

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let now = 1_700_000_000u64;
let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

// ログイン時: token にクライアントのフィンガープリントを束縛する
let ctx = RequestContext {
    token: "token-abc",
    subject: "user-42",
    fingerprint: "203.0.113.7|Mozilla/5.0",
    location: Some("CN-BJ"),
    coords: Some((39.90, 116.40)),
    signature: None,
    at: Some(now),
};
guard.bind(&ctx, now)?;

// リクエストごと: 検証して判定を受け取る
let verdict = guard.verify(&ctx, now);
match verdict.decision {
    Decision::Allow => {}      // 通過
    Decision::Challenge => {}  // 追加検証（MFA など）
    Decision::Block => {}      // 遮断
}
```

- `SessionGuard<S: SessionStore>` — `bind` / `verify` / `revoke` / `revoke_all` / `rotate`
- `SessionVerdict` — `decision: Decision`（`Allow` / `Challenge` / `Block`）、`severity`、`threats: Vec<SessionThreat>`
- `SessionConfig` — `ttl_secs`（既定 3600）、`impossible_travel_kmh`（既定 900.0）、`timestamp_skew_secs`（既定 300）
- `SessionStore` trait と `MemoryStore`

**fail-closed** — ストレージ障害時は `SessionThreat::StoreUnavailable` を伴う `Decision::Block` を返し、決して通しません。認証ゲートが fail-open だと、ストレージを落とすだけで認証を迂回できてしまうためです。

`token` と `signature`（MAC）は呼び出し側が用意し、`location` / `coords` も呼び出し側が解析して渡します。ライブラリの依存を `regex` のみに保つため、token の発行も署名検証も geo データベースも持ちません。

## レート制限と封鎖 (`throttle`)

スライディングウィンドウでの失敗回数カウント、閾値到達時の封鎖、アカウントロックを担います。

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let now = 1_700_000_000u64;
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining } => {
        // X-RateLimit-* に載せる。remaining == 0 なら本リクエストは拒否する
    }
    ThrottleDecision::Banned { until } => { /* now >= until で解除済み */ }
    ThrottleDecision::Unavailable => { /* バックエンド障害。判断は呼び出し側に委ねる */ }
}

// 認証の失敗・成功を記録してウィンドウを進める
throttle.record_failure("user:42", now)?;
throttle.record_success("user:42")?;
```

- `Throttle<S: ThrottleStore>` — `check` / `record_failure` / `record_success` / `reset` / `purge_expired`
- `ThrottleConfig` — `threshold`（既定 5）、`window_secs`（既定 60）、`ban_secs`（既定 900）
- `ThrottleStore` trait と `MemoryThrottleStore`

`Allow { remaining: 0 }` は「あと 1 回試せる」ではなく「本リクエストを拒否すべき」を意味します。

**可用性側の例外** — ストレージ障害時は `ThrottleDecision::Unavailable` を返し、`Banned` にはしません。全ユーザーを締め出すのは自己 DoS であり、レート制限は主たる認証ゲートではなく多層防御だからです。`SessionGuard` の fail-closed とは意図的に異なり、この分岐は `check` に固定されています（`Err` が `Banned` に写像されることはありません）。

**ストレージ** — 両モジュールとも `SessionStore` / `ThrottleStore` という trait でバックエンドを抽象化しています。多インスタンス構成ではこの trait を実装して Redis などを差し込んでください。

## リスクスコアリング (`score`)

個々の検出結果は「その攻撃があった」ことしか語りません。`score` はそれらを重み付きで合算し、観測可能なリスク値に変えます。

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let assessment = scanner.assess("<script>alert(1)</script>");

println!("{} / {} / {}", assessment.level, assessment.score, assessment.results);
// CRITICAL | HIGH | MEDIUM | LOW | NONE
```

- `RiskLevel` — `None` / `Low` / `Medium` / `High` / `Critical`
- `RiskAssessment` — `level`、`score`（重みの合計）、`results`（合算に参加した件数）
- `Scanner::assess(&str) -> RiskAssessment`、および自由関数 `score::assess(&[DetectionResult])`

重みは `Critical`=100、`High`=40、`Medium`=15、`Low`=5 です。`Critical` が 1 件でもあれば合算を待たず `Critical`、それ以外は合計点で `Low`（1〜14）/ `Medium`（15〜39）/ `High`（40〜99）に分かれます。`Low` 3 件が `Medium` に上がるように、低リスク信号の重ね掛けが反映されます。

## モジュールパス

| モジュール | パス | 検出器数 |
|------|------|---------|
| コア | `src/lib.rs` `result.rs` `scanner.rs` | — |
| インジェクション | `src/injection/` | 11 |
| プロトコル | `src/protocol/` | 11 |
| データ | `src/data/` | 7 |
| ファイル | `src/file/` | 3 |
| セッション | `src/session/` | — |
| レート制限 | `src/throttle/` | — |
| スコアリング | `src/score.rs` | — |

## 性能

全 32 検出器でのスキャンは数十 µs/回です。値は CPU、検出器の数、入力長に依存するため、自分のハードウェアと負荷で実測してください。高スループットのシナリオ（API ゲートウェイ、ログパイプライン）では、`scan_with()` で対象検出器を絞ることを検討してください。

各検出器の正規表現は `LazyLock` の `Vec<Regex>` で保持され、プロセスにつき 1 回だけコンパイルされます（2 回目以降のスキャンにはコンパイル費用がかかりません）。
