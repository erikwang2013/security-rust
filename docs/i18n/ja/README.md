<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Rust で書かれた攻撃検出ライブラリ。インジェクション攻撃、プロトコル攻撃、データ/シリアライゼーション攻撃、ファイル/機密データ漏洩の 4 大カテゴリ、全 32 個の検出器をカバーします。加えて、セッションセキュリティ (`session`)、レート制限とアカウント封鎖 (`throttle`)、リスクスコアリング (`score`) の 3 モジュールを公開します。外部フレームワーク依存ゼロ、依存クレートは `regex` のみです。

プロジェクトのペット **甲哨 Sentri**（[`pet.svg`](../../pet.svg)）—— 32 枚の甲板が 32 個の検出器に対応します。報告するだけで、遮断はしません。

---

## プロジェクトのペット: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri —— security-rust のプロジェクトペット" width="340">

虫眼鏡と立て札を掲げた見張りのカニ。この姿は飾りではなく、本ライブラリの設計をそのまま絵にしたものです:

| 造形 | 対応する設計 |
|------|---------|
| 甲殻の 4 行 × 8 枚の甲板 | 32 個のステートレス検出器。4 行 = インジェクション / プロトコル / データ / ファイルの 4 大分類 |
| 左の鋏の虫眼鏡 | **見る**役 —— `Detector::detect()` はスキャンのみを行い、ヒットすれば証拠を 1 件返す |
| 右の鋏の立て札（`已上报` ——「報告済み」） | **報告する**役 —— `DetectionResult` を返し、例外も投げず、呼び出しチェーンも止めない |
| 鋏は決して挟まない | 判定権は呼び出し側にある。唯一の例外は `SessionGuard` で、これは本当に `Block` する |
| 片眼鏡 | 監査者の職業病 —— どの結論にも `matched_pattern` と `offset` が付き、元の入力の位置まで辿れる |
| 銘板の `deps: regex ×1` | ゼロ依存の約束 —— `[dependencies]` は常に `regex` のみ |

座右の銘: **報告するだけで、遮断はしない。**

この姿は `include_str!` でクレートに同梱されています（実行時コストゼロ、使わなければリンクもされません）。ASCII 版はそのまま端末やログに出力できます:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## プロジェクト構成

```
security-rust/
├── src/
│   ├── lib.rs              Detector trait（唯一の契約）、regex_detect ヘルパー、クレートのドキュメント
│   ├── scanner.rs          Scanner / ScannerBuilder: デフォルトで 32 個の検出器を装備
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            リスクスコアリング: 重み付き加算 + 段階分け → RiskAssessment
│   ├── pet.rs              プロジェクトのペット（NAME / TAGLINE / ASCII / SVG）
│   ├── injection/          インジェクション系検出器 11 個
│   ├── protocol/           プロトコル系検出器 11 個
│   ├── data/               データ系検出器 7 個
│   ├── file/               ファイル系検出器 3 個
│   ├── session/            SessionGuard + SessionStore（guard / store / geo）
│   └── throttle/           Throttle + ThrottleStore（guard / store）
├── tests/                  統合テスト 7 スイート: セッション、レート制限、ライフサイクル、不変条件、ロバスト性、エンドツーエンド、多次元レート制限
├── examples/
│   ├── waf.rs              エンドツーエンドパイプラインの例（スキャン → レート制限 → セッション → 判定）
│   └── axum_middleware.rs  axum ミドルウェア組み込みリファレンス
├── docs/
│   ├── API.md              完全な API リファレンス
│   ├── OWASP-COVERAGE.md   OWASP の各攻撃カテゴリとのカバレッジ対応表
│   ├── pet.svg             プロジェクトのペットの意匠
│   ├── diagrams/           アーキテクチャ / 機能 / ライフサイクルの 3 図（SVG）
│   ├── i18n/               12 言語の README と API ドキュメント
│   └── ...                 寄付 QR コード、コードレビューとテストレポート
└── Cargo.toml              唯一の実行時依存: regex
```

---

## 設計思想

### なぜ「検出」であり「遮断」ではないのか

本ライブラリの検出器は**純粋な入力スキャナ**として位置づけられています。文字列を受け取り、構造化された検出結果を返します。どの Web フレームワークにも紐づかず、HTTP リクエスト/レスポンスの解析も行わず、リアルタイム遮断も実装しません。これにより、WAF ルールエンジン、ログ監査、API ゲートウェイ前置検証、CLI セキュリティスキャンツールなど、あらゆる処理チェーンに組み込むことができます。

`session` と `throttle` はこの例外で、状態と識別情報を扱います。両者は意図的に `Detector` trait を実装していません —— 「token + フィンガープリント + 位置 + 時刻」という複合入力は、単一文字列を受け取る `Detector::detect(&str)` では表現できないためです。

### アーキテクチャ原則

- **単一責任** — 各検出器は 1 種類の攻撃タイプのみを担当し、内部にコンパイル済みの正規表現パターンセットを保持
- **統一インターフェース** — `Detector` trait が全検出器の唯一の契約: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **デフォルト網羅** — `Scanner::default()` で全 32 個の検出器を一括装備、ゼロ設定で利用可能
- **任意設定** — `Scanner::builder()` によるカスタマイズをサポート、`.with_detector()` で検出器を選択的に装備
- **有状態モジュールの分離** — `session` / `throttle` は意図的に `Detector` trait を実装しない。有状態かつ識別情報に依存するため、`detect()` の契約では表現できない。ストレージは trait（`SessionStore` / `ThrottleStore`）で抽象化し、多インスタンス構成ではそれを実装して Redis などに接続する

### トレードオフ

| 判断 | 選択 | 理由 |
|------|------|------|
| 正規表現 vs パーサー | 正規表現 | 検出シナリオでは速度優先。変形/迂回パターンへのカバレッジも優れる |
| 先着順報告 vs 全量検出 | 全量検出 | 1 つの入力が複数の攻撃を同時にトリガーし得るため、見逃しを防ぐ |
| ゼロ依存 vs serde 導入 | ゼロ依存 | 依存クレートは `regex` のみ。コンパイル高速、サイズ小 |
| 依存ゼロ vs 利便性 | 依存ゼロ | token と署名は呼び出し側が用意し、位置情報（緯度経度）も呼び出し側が解析する。その代わり、依存の追加も暗黙の I/O もない |
| fail-closed vs 可用性 | 用途で分ける | `SessionGuard` はストレージ障害時に `Decision::Block` を返す（fail-closed、絶対に通さない）。`Throttle` は `ThrottleDecision::Unavailable` を返して判断を呼び出し側に委ねる —— 全ユーザーを止めるのは自己 DoS であり、レート制限は主たる認証ゲートではないため |

---

## 設計アーキテクチャ

<img src="../../diagrams/architecture.svg" alt="security-rust のアーキテクチャ図: 呼び出し側 → 検出層 → スコアリング層 → ガード層 → ストレージ層" width="900">

5 層を上から下へ: **呼び出し側**（WAF / ゲートウェイ / 監査 / CLI）→ **検出層**（`Scanner` が `Vec<Box<dyn Detector>>` を保持、4 大分類で計 32 個）→ **スコアリング層**（`score::assess`）→ **ガード層**（`SessionGuard` / `Throttle`、それぞれ store trait を 1 つ束ねる）→ **ストレージ抽象**（内蔵 `MemoryStore`、Redis は呼び出し側が実装）。
*(図中の注釈は中国語です。ラベルは API 名です。)*

`Detector` trait は検出層唯一の契約です: `fn detect(&self, input: &str) -> Option<DetectionResult>`。`session` / `throttle` / `score` はこれを実装していません —— 入力が単一の文字列ではないか（token + フィンガープリント + 位置 + 時刻）、生の入力ではなくスキャン結果を消費するためで、それぞれが独自に答えます（詳細は後述）。図の右側にある赤い戻り線が本ライブラリの境界です: **判定結果は呼び出し側に戻って実行され**、ライブラリ自身はリクエストには触れません。

### モジュールの役割

| モジュール | パス | 検出器数 | 役割 |
|------|------|---------|------|
| コア | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait、`DetectionResult`、`Scanner`/`ScannerBuilder` |
| インジェクション | `src/injection/` | 11 | XSS、SQL インジェクション、コマンドインジェクション、NoSQL、LDAP、XPATH、JNDI、SSI、GraphQL、SSTI、フォーマット文字列 |
| プロトコル | `src/protocol/` | 11 | SSRF、XXE、ヘッダーインジェクション（CRLF 含む）、Host ヘッダー攻撃、リクエストスモグリング、オープンリダイレクト、CORS、WebSocket、DNS リバインディング、Log4Shell、HTTP パラメータ汚染 |
| データ | `src/data/` | 7 | PHP デシリアライゼーション、CSV インジェクション、スプレッドシート数式インジェクション、メールヘッダーインジェクション、JWT 攻撃、プロトタイプ汚染、ReDoS |
| ファイル | `src/file/` | 3 | パストラバーサル、悪意あるファイルアップロード、機密データ漏洩 |
| セッション | `src/session/` | — | `SessionGuard`、`RequestContext`、`SessionVerdict`、`SessionStore`/`MemoryStore` —— クライアントによる乗っ取り、データ改竄、不可能旅行、token 失効の判定 |
| レート制限 | `src/throttle/` | — | `Throttle`（`check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`）、`ThrottleDecision`、`ThrottleOutcome`、`ThrottleStore`/`MemoryThrottleStore` —— スライディングウィンドウ、閾値での封鎖、アカウントロック |
| スコアリング | `src/score.rs` | — | `RiskLevel`、`RiskAssessment`、`Scanner::assess()` —— 低リスク信号を集約し、観測可能なリスク値にする |

### 検出結果の構造

`DetectionResult` は `attack_type`、`category`、`severity`、`matched_pattern`、`offset`、`message` の 6 項目を構造化して返します。完全な定義は [API リファレンス](./API.md) を参照してください。

---

## 実装機能

<img src="../../diagrams/features.svg" alt="security-rust の機能図: インジェクション 11、プロトコル 11、データ 7、ファイル 3、加えて状態を持つ 3 モジュール" width="900">

32 個の検出器は 4 大分類ごとに装備され、`Scanner::default()` でゼロ設定のまま全量有効になります。下表は各検出器がカバーする攻撃パターンと重大度を列挙します。重大度は単一のヒットの危険度を示すもので、集約後の全体リスクは `Scanner::assess()` を参照してください。
*(図中の注釈は中国語です。ラベルは API 名です。)*

### インジェクション攻撃（11 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **xss** | `<script>`、`onerror=` などのイベントハンドラ、`javascript:` 疑似プロトコル、`<svg>`/`<iframe>` タグ、CSS `expression()`、`eval()`、`document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`、`sleep()`/`benchmark()`/`pg_sleep()` 遅延インジェクション、`information_schema` 列挙、`exec sp_`/`xp_` ストアドプロシージャ、ブール型ブラインドインジェクションパターン `' OR '1'='1`、`LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | バッククォートコマンド、`$()` サブコマンド、パイプによる連鎖実行、`/dev/tcp` リバースシェル、`passthru()`/`shell_exec()`/`system()` PHP 関数、`cmd.exe`/`powershell` 呼び出し | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` オペレーター、`$or` インジェクション、認証バイパス `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(\|` `(!` フィルターオペレーター、`*(cn=` 属性列挙、`objectClass`/`uid` インジェクション | High |
| **xpath_injection** | `' or '1'='1` ブール型バイパス、`' or true()` 関数インジェクション、`'] \| '` ノードトラバーサル | High |
| **jndi_injection** | `${jndi:ldap://`、`${lower:j}` 難読化、`${upper:j}` 難読化、`${::-j}` 空文字列難読化、`${env:}` 環境変数ルックアップ、`${sys:}` システムプロパティ | Critical |
| **ssi_injection** | `<!--#exec cmd=` コマンド実行、`<!--#include file=` ファイルインクルード、`<!--#echo var=` 変数出力、`<!--#fsize`/`<!--#flastmod` ファイル情報 | High |
| **graphql_injection** | `__schema`/`__type` イントロスペクションクエリ、深いネストによる DoS（5 層以上） | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` の**デリミタ内での評価**（`{{7*7}}`、`${7*7}`、`{{config`、`${T(java.lang.Runtime)}`）、ERB `<%=` `<%@`、Velocity `#set()`、Python エスケープチェーン `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`。デリミタ自体は信号ではなく、`${x}` のような単なるプレースホルダーは報告しない | Critical |
| **format_string** | `%n`/`%hn`/`%lln` メモリ書き込み変換子、`%99999999d` 幅爆弾、連続 `%x%x%x`・区切り付き `%08x.%08x.%08x.%08x` のスタック読み出し、連続 `%s` | Medium |

### プロトコル・リクエスト攻撃（11 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` クラウドメタデータ、RFC1918 内部 IP（10.x、172.16-31.x、192.168.x）、`127.x` loopback、`::1` IPv6 loopback、`0.0.0.0`、`gopher://`/`dict://`/`ftp://`/`file://` 危険なプロトコル | Critical |
| **xxe** | `<!ENTITY` エンティティ宣言、`SYSTEM`/`PUBLIC` 外部参照、`%` パラメーターエンティティ、`<!DOCTYPE` DTD 宣言 | Critical |
| **header_injection** | `%0d%0a` URL エンコード CRLF、`\r\n` 生 CRLF インジェクション、`%0d`/`%0a` の逆順ペア（LF-CR） | High |
| **host_header** | 複数 Host ヘッダーインジェクション、`X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` ポイズニング、CRLF による Host 運搬 | High |
| **request_smuggling** | 二重 `Transfer-Encoding` ヘッダー、`Content-Length: 0` スモグリング、`\r\n0\r\n` chunked 終端難読化 | High |
| **open_redirect** | `//evil.com` プロトコル相対 URL、`javascript:`/`data:text/html` 疑似プロトコルによるリダイレクト | Medium |
| **cors** | `Access-Control-Allow-Origin: null`、`Origin: null`（サンドボックス iframe と CSWSH の正規の指標）、および `Access-Control-Allow-Origin: *` と `Access-Control-Allow-Credentials: true` の**同時出現**。単独で現れる分には公開 API や静的アセットでは正常であり報告しない | Medium |
| **websocket** | `Origin: null` と WebSocket アップグレードの同時出現（CSWSH）、`ws://` がループバック / プライベート / リンクローカルアドレスを指す場合（クラウドメタデータエンドポイント `169.254.169.254` を含む） | High |
| **dns_rebinding** | Host ヘッダーが `127.x`/`10.x`/`192.168.x`/`172.16-31.x` 内部 IP、`localhost`、`::1`、`0.0.0.0` | High |
| **log4shell** | `${lower:j}`/`${upper:J}` の大小文字折り畳み、`${::-j}` のプレフィックス折り畳み、lookup 展開後に `ndi:` が現れる混淆、`${${...}}` の入れ子展開、URL エンコード形態 `%24%7b...%7d` | Critical |
| **hpp** | `;` と `&` の混用（`a=1&b=2;c=3`）、パラメータキーの重複 —— パーサーごとに解釈が食い違う HTTP パラメータ汚染 | Medium |

### データ・シリアライゼーション攻撃（7 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **deserialization** | PHP `O:数字:`/`C:数字:` シリアライズオブジェクト、`a:数字:{` 配列、`unserialize()` 呼び出し、`__wakeup`/`__destruct`/`__toString` などのマジックメソッド | Critical |
| **csv_injection** | セル先頭の `=`/`+`/`-`/`@` 数式文字（タブと復帰は**区切り文字**であり数式の開始ではない）、区切り文字 `,`/`;`/`\t` の直後に続く `=`、DDE 動的データ交換、`cmd\|` コマンドパイプ、`@SUM()` 関数 | Medium |
| **mail_header** | `Bcc:`/`Cc:` ブラインドカーボンコピーインジェクション、`From:` 多重送信者、`MIME-Version:`/`Content-Type: multipart` MIME ヘッダーインジェクション、`boundary=` バウンダリー操作 | Medium |
| **jwt_attack** | `alg: none` 空アルゴリズムバイパス、`kid` パストラバーサルインジェクション、空署名セグメント、空 payload セグメント | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` プロトタイプチェーン汚染、`__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` プロパティハイジャック | High |
| **formula_injection** | セル先頭の `=cmd` + パイプ（コマンド実行）、`HYPERLINK()`/`IMPORTXML()`/`WEBSERVICE()`/`RTD()` などデータ持ち出し・ローカル実行関数、DDE セル参照（`!A0`）、`DDE(` ペイロード、`@SUM(` などの旧式 `@` 数式 —— CSV の粗粒度層に対し、実行・持ち出し可能なペイロードだけを拾う精密層 | High |
| **redos** | `(a+)+`/`(a*)*` の量詞の入れ子、`(a+){2,}`、`\d` と `\w` のような重複する文字クラス分岐、`(x\|)` の空分岐、先頭分岐が単一文字でプレフィックスが重なる `(a\|ab)*` —— 指数関数的バックトラックを起こす正規表現 | Medium |

### ファイル・機密データ（3 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` ディレクトリトラバーサル、`%2e%2e` URL エンコード迂回、`php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` プロトコルラッパー、`%00` ヌルバイト切り詰め | Critical |
| **upload** | `<?php`/`<?=` PHP タグ、`<%@`/`<%=` ASP タグ、`eval($_`/`system($_`/`exec($_`/`passthru($_` バックドアパターン、`$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` スーパーグローバル変数、`base64_decode()` エンコード迂回 | Critical |
| **data_leak** | 16 桁クレジットカード PAN（Visa/MasterCard/AmEx/Discover/JCB/Diners）、AWS Access Key `AKIA...`、PEM 秘密鍵ヘッダー `-----BEGIN`、OpenAI/LLM API Key `sk-...`、データベース接続文字列 `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`、JWT Token | Critical |

---

## ライフサイクル

<img src="../../diagrams/lifecycle.svg" alt="security-rust の 3 つのライフサイクル: スキャン、セッション、レート制限" width="900">

3 つのライフサイクルは互いに独立しており、唯一の合流点は呼び出し側のリクエスト処理関数です:

| ライフサイクル | 起点 | 終点 | 状態の置き場所 |
|---------|------|------|---------|
| **スキャン** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | ステートレス、呼び出しごとに独立 |
| **セッション** | `SessionGuard::bind()` が `SessionRecord` を書き込む | リクエストごとに `verify()` → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore`（内蔵 `MemoryStore`） |
| **レート制限** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore`（内蔵 `MemoryThrottleStore`） |

間違えやすい 2 つの境界:

- **`remaining == 0` はこのリクエストを拒否すべきという意味** —— 枠を使い切ったのであって「あと 1 回試せる」ではありません。`X-RateLimit-*` に書くときは逆にしないこと。
- **ストレージ障害時の扱いは左右で逆**: `SessionGuard` は fail-closed（`StoreUnavailable` ⇒ `Block`、絶対に通さない。そうでなければ攻撃者が障害を誘発するだけで判定の一種類を丸ごと差し替えられてしまう）、`Throttle` は fail-open（`Unavailable` を呼び出し側に委ねる。バックエンドの揺らぎで全ユーザーを締め出すのは自己 DoS であり、主ゲートの `SessionGuard` は依然として止めている）。これは書き込まれた設計であり、書き忘れたフォールバックではありません。

---

## 使用説明

ゼロ設定で使用可能です:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

リスクスコアリングはヒットの一覧を 1 つの等級にまとめ、複数の低リスク信号が黙って無視されるのを防ぎます:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — 生の重み付きスコア
```

完全な API リファレンス（インストール、選択的スキャン、カスタム設定、リスクスコアリング、重大度表示、セッションセキュリティ、レート制限と封鎖、性能）は [API リファレンス](./API.md) を参照してください。

### セッションセキュリティ（`session`）

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // クライアントのフィンガープリント。ログイン時に束縛する
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC は呼び出し側が署名する
    at: None,
};

// ログイン: セッションを作成 + フィンガープリントを束縛 + 位置を記録。異地点は verdict に影響するだけで、ログインは阻まない
guard.bind(&login, 1_700_000_000).unwrap();

// リクエストごとの検証: 同じ token でフィンガープリントが変われば ⇒ クライアント乗っ取り
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* 通過 */ }
    Decision::Challenge => { /* 通過するが二次検証を要求: 異地点、時刻のずれ、署名の不一致 */ }
    Decision::Block => { /* 拒否 */ }
}
```

### レート制限と封鎖（`throttle`）

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key は呼び出し側が構築して正規化する。生の入力をそのまま key にしないこと
let now = 1_700_000_000;

// 実際のリクエストには IP とアカウントの 2 つの次元がある。check_any は一度に問い合わせ、厳しさの順に併合する
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining は X-RateLimit-* に載せられる。**remaining == 0 は本リクエストを拒否すべきという意味**
    ThrottleDecision::Allow { remaining } => { /* 残り枠 remaining */ }
    // now >= until になれば解除済みとみなす
    ThrottleDecision::Banned { until } => { /* 封鎖中、until で解除 */ }
    // バックエンド障害: 本モジュールは呼び出し側の代わりに決めない（通過 + 警告を推奨）
    ThrottleDecision::Unavailable => { /* レート制限バックエンドが利用不可 */ }
}

// 認証失敗を記録: threshold に達すると封鎖。返り値は ThrottleOutcome（2 状態）で、
// ストレージ障害は Err になる —— 決して実行されない Unavailable アームのためにコードを書き足さなくてよい
let _ = throttle.record_failure(key, now);
```

---

## 開発

```bash
# ビルド
cargo build --release

# テスト（494 件: ユニット 365 + 統合 128 + ドキュメントテスト 1）
cargo test

# エンドツーエンドパイプラインの例（スキャン → レート制限 → セッション → 判定）
cargo run --example waf

# コードチェック
cargo clippy -- -D warnings
```

---

## 寄付 / スポンサー

このプロジェクトがお役に立つようでしたら、任意の寄付でサポートをお願いします。

| 支付宝 (Alipay) | 微信支付 (WeChat Pay) |
|--------|---------|
| ![支付宝](alipay.png) | ![微信支付](weixinpay.png) |

### グローバル送金（国際送金）

【受取人情報】
- 受取人名：WANG KEXUN
- 受取口座番号：881015918251

【受取銀行】
- ZA Bank SWIFT Code：AABLHKHHXXX
- 銀行名：ZA Bank Limited
- 銀行コード：387
- 銀行所在地：Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【クロスボーダー送金代理銀行（必要な場合）】

こちらはクロスボーダー送金の代理銀行（中継銀行）情報であり、受取銀行の情報ではありません。代理銀行情報の提供が必要かどうかは、送金銀行にお問い合わせください。

香港ドル、人民元、米ドルでの送金時の代理銀行は Citibank です:
- 銀行名：Citibank N.A. Hong Kong
- SWIFT Code：CITIHKHXXXX
- 銀行コード：006
- 支店名：Hong Kong Branch
- 支店コード：391
- 銀行所在地：Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

その他通貨での送金時の代理銀行は BNY Mellon です:
- 銀行名：THE BANK OF NEW YORK MELLON
- SWIFT Code：IRVTUS3NXXX
- 銀行所在地：THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## ライセンス

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
