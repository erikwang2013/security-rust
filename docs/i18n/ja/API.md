<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API リファレンス

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語 (本页)](./API.md)

---

## コア Trait

### `Detector`

全検出器の唯一の契約:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## 二段階信号：強シグナルと弱シグナル

32 個の検出器のうち 18 個がパターンを二段階に分けています（ソース内の `STRONG_PATTERNS` / `WEAK_PATTERNS`）。`DetectionResult` のフィールド構造は変わらず、変わるのは `severity` の値です:

| 段階 | 判定基準 | `severity` | 単条で拒否ラインを越えられるか |
|------|------|-----------|------------------|
| **強シグナル** | その形態自体が攻撃由来しかあり得ない | 検出器が宣言した等級 | 越えられる |
| **弱シグナル** | そのトークンが「出現」しただけ。正常な内容にも溢れている | 常に `Severity::Low`（5 点） | **越えられない** |

同じ検出器・同じ `attack_type` で、違うのは `severity` だけです。`detect()` はまず強档を試し、強档が当たらなければ弱档を試すため、**各検出器は最大 1 件しか返しません**。弱シグナルも依然として検出され、黙って漏れることはありません。

`DetectionResult` 自体は段階を区別しません —— あるヒットが強か弱かは `severity == Severity::Low` で分かります（弱档が `Low` を報告する唯一の源です）。参考パイプラインの拒否ラインは 40 点（`risk.level >= RiskLevel::High`、[`examples/waf.rs:166`](../../../examples/waf.rs)）で、単条の弱シグナルは 5 点しかなくこの分岐に入りません。

弱シグナルの背後にある攻撃を見るには、`assess()` が複数の検出器のヒットを重ねます:

```rust
let scanner = Scanner::default();

// 3 件の弱シグナルが 3 つの異なる検出器にヒット。重ねてようやく Medium（15 点）に届くが High 未満
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

弱シグナルに降格された形態の例（完全なリストは各検出器の `WEAK_PATTERNS`）: `<script src=...>`、単段の `../`、行頭の `-2`、裸の `__proto__`、`${env:}`、`X-Forwarded-Host`、`Host: localhost`、裸の `10.0.0.5`、`//evil.com`、`information_schema`。

判定基準は**形態**であってファイル名ではありません: 同じ `../` でも、単段の `../x` は `Low`、多段の `../../` は `Critical` を報告します（[`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)）。各検出器がどこまで到達できるかは下の各表と [README](./README.md) の機能表を参照してください。

## Scanner

### インストール

```toml
[dependencies]
security-rust = "2.1.1"
```

### クイックスタート

```rust
use security_rust::Scanner;

fn main() {
    // ゼロ設定: 全 32 個の検出器を装備
    let scanner = Scanner::default();

    // 入力をスキャンし、検出されたすべての攻撃を返す（各検出器は最大 1 件）
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 出力:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // 弱シグナルは同じ検出器・同じ attack_type を通り、severity だけが Low になる
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

`Severity` 以外の状態ラベルも `Display` を実装しており、いずれも大文字で出力されます: `Decision`(`ALLOW` / `CHALLENGE` / `BLOCK`)、`SessionThreat`(例: `impossible travel (11205 km/h)`)、`AttackCategory`(小文字。例: `injection`)、`ThrottleDecision`(`ALLOW` / `BANNED` / `UNAVAILABLE`)、`ThrottleOutcome`(`ALLOW` / `BANNED`)。

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
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

- `SessionGuard<S: SessionStore>` — `bind` / `verify` / `revoke` / `revoke_all` / `rotate` / `purge_expired`（戻り値は**セッションの件数のみ**で、回収されたログイン履歴は含まない）
- `SessionVerdict` — `decision: Decision`（`Allow` / `Challenge` / `Block`）、`severity: Option<Severity>`（通過時は `None`）、`threats: Vec<SessionThreat>`
- `SessionConfig` — `ttl_secs`（既定 3600）、`impossible_travel_kmh`（既定 900.0）、`timestamp_skew_secs`（既定 300）
- `SessionStore` trait と `MemoryStore`

**fail-closed** — ストレージ障害時は `SessionThreat::StoreUnavailable` を伴う `Decision::Block` を返し、決して通しません。認証ゲートが fail-open だと、ストレージを落とすだけで認証を迂回できてしまうためです。

`token` と `signature`（MAC）は呼び出し側が用意し、`location` / `coords` も呼び出し側が解析して渡します。ライブラリの依存を `regex` のみに保つため、token の発行も署名検証も geo データベースも持ちません。

`subject` は **`bind` だけが使い、`verify` は完全に無視します** — リクエストごとに検証される身元は常にサーバー側の `SessionRecord` から取られ（異地点履歴は `record.subject` で集計されます）、呼び出し側が渡した `subject` は信頼できません。したがってミドルウェアから `subject: ""` を渡すのは正当です（非空を要求するのは `bind` のほうです）。まさにそのため、リクエストヘッダーのユーザー識別子をここに **絶対に** 入れてはいけません。今日は判定に届かなくても、将来のリファクタリングがそれを保つ義務はありません。

## レート制限と封鎖 (`throttle`)

スライディングウィンドウでの失敗回数カウント、閾値到達時の封鎖、アカウントロックを担います。

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let now = 1_700_000_000u64;
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining } => {
        // X-RateLimit-* に載せる。remaining == 0 なら本リクエストは拒否する
    }
    ThrottleDecision::Banned { until } => { /* now >= until で解除済み */ }
    ThrottleDecision::Unavailable => { /* バックエンド障害。判断は呼び出し側に委ねる */ }
}

// 複数のディメンションを併合する（例: IP + アカウント）。最も厳しい結果が採用される
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);  // ThrottleDecision

// 認証の失敗・成功を記録してウィンドウを進める
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* ストレージ障害 */ }
}
throttle.record_success("acct:user-42")?;
```

- `Throttle<S: ThrottleStore>` — `check` / `check_any` / `record_failure` / `record_success` / `reset` / `purge_expired`
- `ThrottleConfig` — `threshold`（既定 5）、`window_secs`（既定 60）、`ban_secs`（既定 900）
- `ThrottleStore` trait と `MemoryThrottleStore`

`Allow { remaining: 0 }` は「あと 1 回試せる」ではなく「本リクエストを拒否すべき」を意味します。

**可用性側の例外** — ストレージ障害時は `check` / `check_any` が `ThrottleDecision::Unavailable` を返し、`Banned` にはしません。全ユーザーを締め出すのは自己 DoS であり、レート制限は主たる認証ゲートではなく多層防御だからです。`SessionGuard` の fail-closed とは意図的に異なります。`Unavailable` は `check` / `check_any` だけが返し、`record_failure` はこの変種を持たない `ThrottleOutcome` を返します（ストレージ障害は `Err(StoreError)` になります）。`check_any` は複数ディメンションを併合し、`Banned` があれば最も遅い `until` で `Banned`、なければ `Unavailable`、なければ最小の `remaining` で `Allow` を返し、空のリストは `Allow { remaining: 0 }` になります。

**ストレージ** — 両モジュールとも `SessionStore` / `ThrottleStore` という trait でバックエンドを抽象化しています。多インスタンス構成ではこの trait を実装して Redis などを差し込んでください。

## リスクスコアリング (`score`)

個々の検出結果は「その攻撃があった」ことしか語りません。`score` はそれらを重み付きで合算し、観測可能なリスク値に変えます。

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");

println!("{} / {} / {}", assessment.level, assessment.score, assessment.results);
// CRITICAL | HIGH | MEDIUM | LOW | NONE
```

- `RiskLevel` — `None` / `Low` / `Medium` / `High` / `Critical`
- `RiskAssessment` — `level`、`score`（重みの合計）、`results`（合算に参加した件数）
- `Scanner::assess(&str) -> RiskAssessment`、および自由関数 `score::assess(&[DetectionResult])`

重みは `Critical`=100、`High`=40、`Medium`=15、`Low`=5 です。`Critical` が 1 件でもあれば合算を待たず `Critical`、それ以外は合計点で `Low`（1〜14）/ `Medium`（15〜39）/ `High`（40〜99）に分かれます。`Low` 3 件が `Medium` に上がるように、低リスク信号の重ね掛けが反映されます。

**これが弱シグナルの唯一の昇格経路です** —— 単条の弱シグナルは 5 点で、40 点の拒否ラインは永遠に越えられません。越えられるのは、複数（異なる検出器から）が重なったときだけです。したがって複数次元の入力を同じ `Scanner` にまとめて渡す方が、単一フィールドだけをスキャンするより弱シグナルの背後にある攻撃が見えます。逆に、短いフィールド 1 つだけをスキャンするなら弱シグナルへの対処は一切不要です。

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
| ペット | `src/pet.rs` | — |

## 既知の上限

以下は**既知であり、意図的に残している**境界です。未修正の欠陥ではありません。変更する前に根拠を読んでください —— いずれも実測に基づき、かつ誰かが締め上げようとして同じ壁にぶつかったものです。

### `dns_rebinding` は報告するだけで、遮断しない

判定基準は「`Host:` ヘッダーに内部アドレスが現れる」ことですが、同じ形は k8s の pod 間呼び出し（`Host: 10.244.1.5:8080`）、ローカル開発（`Host: localhost:8000`）、Docker のコンテナネットワーク通信（`172.18.0.2`）のすべてでもあります。本当の rebinding が見るのは「公開ドメイン名 + 解決結果が内向き」であり、ブラウザが送る `Host` はまさにその公開ドメイン名です —— **単一の文字列からは解決履歴が見えない**ため、この検出器が測る形態は攻撃の形態と重なりません。締め上げようがありません。したがって検出器全体が弱档で、一律 `Low` を報告し、何条重ねても単独では拒否ラインを越えません。防御は解決**後**に結果 IP を突き合わせる場所にあり、文字列層にはありません。

### このライブラリは自分のソース・テスト・ドキュメントをスキャンできない

シグネチャスキャナの天井: 実測で本リポジトリの 298 ファイル中 78 ファイルが拒否ラインを越えますが、それらは**構造上**すべて攻撃文字列を含んでいます —— テストペイロード、検出器ソース自身の正規表現リテラル、そしてこれらのパターンを列挙する README と OWASP の表です。README は `(a+)+` と書いたからといって欠陥にはなりません。自分の成果物をスキャンするには、まずこのコーパスを除外するか、別の判定基準に替える必要があります。

### `upload` は `<%@` / `<?php` を一律 Critical とする

この検出器の契約は「**この blob はサーバー側で実行可能なコードである**」—— 出現した時点で成立するため、強弱の階層を設けていません。JSP ページと JSP webshell の先頭バイトはバイト単位で同じで（`<%@ page language="java" … %>` と `<%@ page import="java.io.*" %>` は同じ形態）、`<%@`/`<%=` を降格することは webshell を拒否ラインの下へ落とすこと —— それは別のやり方で検出を消すことに他なりません。代償は、**現在配信中の**ページ（アップロードされたファイルではなく）をスキャンしてもヒットすることですが、それは入力域の不一致です。

### `path_traversal` は `(?:\.\./){2,}` を Critical とする

monorepo の深い相対パス（`from '../../../shared/domain'`）がヒットします。これ以上締め上げていないのは、攻撃と区別できる唯一の制約が対象ファイル名のリスト（`../etc/passwd` の類）であり、それがシステムファイルしか覆わないためです —— 攻撃側が LFI の対象を変えればすり抜けます。

## 性能

全 32 検出器でのスキャンは数十 µs/回です。値は CPU、検出器の数、入力長に依存するため、自分のハードウェアと負荷で実測してください。高スループットのシナリオ（API ゲートウェイ、ログパイプライン）では、`scan_with()` で対象検出器を絞ることを検討してください。

各検出器の正規表現は `LazyLock` の `Vec<Regex>` で保持され、プロセスにつき 1 回だけコンパイルされます（2 回目以降のスキャンにはコンパイル費用がかかりません）。
