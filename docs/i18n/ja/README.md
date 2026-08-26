<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Rust で書かれた攻撃検出ライブラリ。インジェクション攻撃、プロトコル攻撃、データ/シリアライゼーション攻撃、ファイル/機密データ漏洩の 4 大カテゴリ、全 27 個の検出器をカバーします。外部フレームワーク依存ゼロ、純粋な文字列スキャン。

---

## 設計思想

### なぜ「検出」であり「遮断」ではないのか

本ライブラリは**純粋な入力スキャナ**として位置づけられています。文字列を受け取り、構造化された検出結果を返します。どの Web フレームワークにも紐づかず、HTTP リクエスト/レスポンスの解析も行わず、リアルタイム遮断も実装しません。これにより、WAF ルールエンジン、ログ監査、API ゲートウェイ前置検証、CLI セキュリティスキャンツールなど、あらゆる処理チェーンに組み込むことができます。

### アーキテクチャ原則

- **単一責任** — 各検出器は 1 種類の攻撃タイプのみを担当し、内部にコンパイル済みの正規表現パターンセットを保持
- **統一インターフェース** — `Detector` trait が全検出器の唯一の契約: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **デフォルト網羅** — `Scanner::default()` で全 27 個の検出器を一括装備、ゼロ設定で利用可能
- **任意設定** — `Scanner::builder()` によるカスタマイズをサポート、`.with_detector()` で検出器を選択的に装備

### トレードオフ

| 判断 | 選択 | 理由 |
|------|------|------|
| 正規表現 vs パーサー | 正規表現 | 検出シナリオでは速度優先。変形/迂回パターンへのカバレッジも優れる |
| 先着順報告 vs 全量検出 | 全量検出 | 1 つの入力が複数の攻撃を同時にトリガーし得るため、見逃しを防ぐ |
| ゼロ依存 vs serde 導入 | ゼロ依存 | `regex` + `thiserror` のみに依存。コンパイル高速、サイズ小 |

---

## 設計アーキテクチャ

```
                       ┌──────────────────────────────────┐
                       │             Scanner              │
                       │  ┌────────────────────────────┐  │
    user input ───────►│  │ scan(input)                │  │      Vec<DetectionResult>
                       │  │ scan_with(input, &[...])   │──┼──►──────────────────────►
                       │  └─────────────┬──────────────┘  │
                       │                │                  │
                       │  ┌─────────────▼──────────────┐  │
                       │  │   Vec<Box<dyn Detector>>   │  │
                       │  │   ├─ XssDetector           │  │
                       │  │   ├─ SqlInjectionDetector  │  │
                       │  │   ├─ ... ×27               │  │
                       │  └────────────────────────────┘  │
                       └──────────────┬───────────────────┘
                                      │
       ┌──────────────────────────────┐
       │       Detector trait         │
       │  fn name(&self) -> &str      │
       │  fn detect(&self, &str)      │
       │       -> Option<Result>      │
       └──────────────┬───────────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
  ┌────┴────┐  ┌──────┴──────┐  ┌───┴────┐  ┌────┴────┐
  │injection│  │  protocol   │  │  data  │  │  file   │
  │  10 個  │  │   9 個      │  │ 5 個   │  │  3 個   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

### モジュールの役割

| モジュール | パス | 検出器数 | 役割 |
|------|------|---------|------|
| コア | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait、`DetectionResult`、`Scanner`/`ScannerBuilder` |
| インジェクション | `src/injection/` | 10 | XSS、SQL インジェクション、コマンドインジェクション、NoSQL、LDAP、XPATH、JNDI、SSI、GraphQL、SSTI |
| プロトコル | `src/protocol/` | 9 | SSRF、XXE、ヘッダーインジェクション、Host ヘッダー攻撃、リクエストスモグリング、オープンリダイレクト、CORS、WebSocket、DNS リバインディング |
| データ | `src/data/` | 5 | PHP デシリアライゼーション、CSV 数式インジェクション、メールヘッダーインジェクション、JWT 攻撃、プロトタイプ汚染 |
| ファイル | `src/file/` | 3 | パストラバーサル、悪意あるファイルアップロード、機密データ漏洩 |

### 検出結果の構造

`DetectionResult` は `attack_type`、`category`、`severity`、`matched_pattern`、`offset`、`message` の 6 項目を構造化して返します。完全な定義は [API リファレンス](./API.md) を参照してください。

---

## 実装機能

### インジェクション攻撃（10 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **xss** | `<script>`、`onerror=` などのイベントハンドラ、`javascript:` 疑似プロトコル、`<svg>`/`<iframe>` タグ、CSS `expression()`、`eval()`、`document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`、`sleep()`/`benchmark()`/`pg_sleep()` 遅延インジェクション、`information_schema` 列挙、`exec sp_`/`xp_` ストアドプロシージャ、ブール型ブラインドインジェクションパターン `' OR '1'='1`、`LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | バッククォートコマンド、`$()` サブコマンド、パイプによる連鎖実行、`/dev/tcp` リバースシェル、`passthru()`/`shell_exec()`/`system()` PHP 関数、`cmd.exe`/`powershell` 呼び出し | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` オペレーター、`$or` インジェクション、認証バイパス `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(|` `(!` フィルターオペレーター、`*(cn=` 属性列挙、`objectClass`/`uid` インジェクション | High |
| **xpath_injection** | `' or '1'='1` ブール型バイパス、`' or true()` 関数インジェクション、`'] | '` ノードトラバーサル | High |
| **jndi_injection** | `${jndi:ldap://`、`${lower:j}` 難読化、`${upper:j}` 難読化、`${::-j}` 空文字列難読化、`${env:}` 環境変数ルックアップ、`${sys:}` システムプロパティ | Critical |
| **ssi_injection** | `<!--#exec cmd=` コマンド実行、`<!--#include file=` ファイルインクルード、`<!--#echo var=` 変数出力、`<!--#fsize`/`<!--#flastmod` ファイル情報 | High |
| **graphql_injection** | `__schema`/`__type` イントロスペクションクエリ、深いネストによる DoS（5 層以上） | Medium |
| **ssti** | Jinja2 `{{}}`、FreeMarker `${}`、ERB `<%=` `<%@`、Velocity `#set()`、Python MRO `__mro__`/`__subclasses__()` サンドボックスエスケープ | Critical |

### プロトコル・リクエスト攻撃（9 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` クラウドメタデータ、RFC1918 内部 IP（10.x、172.16-31.x、192.168.x）、`127.x` loopback、`::1` IPv6 loopback、`0.0.0.0`、`gopher://`/`dict://`/`ftp://`/`file://` 危険なプロトコル | Critical |
| **xxe** | `<!ENTITY` エンティティ宣言、`SYSTEM`/`PUBLIC` 外部参照、`%` パラメーターエンティティ、`<!DOCTYPE` DTD 宣言 | Critical |
| **header_injection** | `%0d%0a` URL エンコード CRLF、`\r\n` 生 CRLF インジェクション | High |
| **host_header** | 複数 Host ヘッダーインジェクション、`X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` ポイズニング、CRLF による Host 運搬 | High |
| **request_smuggling** | 二重 `Transfer-Encoding` ヘッダー、`Content-Length: 0` スモグリング、`\r\n0\r\n` chunked 終端難読化 | High |
| **open_redirect** | `//evil.com` プロトコル相対 URL、`javascript:`/`data:text/html` 疑似プロトコルによるリダイレクト | Medium |
| **cors** | `Origin: null` バイパス、`Access-Control-Allow-Origin: *` + Credentials の組み合わせ | Medium |
| **websocket** | `Upgrade: websocket` ハンドシェイク、`Origin: null` クロスドメイン WS、`ws://` 平文接続 | High |
| **dns_rebinding** | Host ヘッダーが `127.x`/`10.x`/`192.168.x`/`172.16-31.x` 内部 IP、`localhost`、`::1`、`0.0.0.0` | High |

### データ・シリアライゼーション攻撃（5 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **deserialization** | PHP `O:数字:`/`C:数字:` シリアライズオブジェクト、`a:数字:{` 配列、`unserialize()` 呼び出し、`__wakeup`/`__destruct`/`__toString` などのマジックメソッド | Critical |
| **csv_injection** | 行頭 `=`/`+`/`-`/`@` 数式文字、DDE 動的データ交換、`cmd|` コマンドパイプ、`@SUM()` 関数 | Medium |
| **mail_header** | `Bcc:`/`Cc:` ブラインドカーボンコピーインジェクション、`From:` 多重送信者、`MIME-Version:`/`Content-Type: multipart` MIME ヘッダーインジェクション、`boundary=` バウンダリー操作 | Medium |
| **jwt_attack** | `alg: none` 空アルゴリズムバイパス、`kid` パストラバーサルインジェクション、空署名セグメント、空 payload セグメント | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` プロトタイプチェーン汚染、`__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` プロパティハイジャック | High |

### ファイル・機密データ（3 検出器）

| 検出器 | 対象パターン | 重大度 |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` ディレクトリトラバーサル、`%2e%2e` URL エンコード迂回、`php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` プロトコルラッパー、`%00` ヌルバイト切り詰め | Critical |
| **upload** | `<?php`/`<?=` PHP タグ、`<%@`/`<%=` ASP タグ、`eval($_`/`system($_`/`exec($_`/`passthru($_` バックドアパターン、`$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` スーパーグローバル変数、`base64_decode()` エンコード迂回 | Critical |
| **data_leak** | 16 桁クレジットカード PAN（Visa/MasterCard/AmEx/Discover/JCB/Diners）、AWS Access Key `AKIA...`、PEM 秘密鍵ヘッダー `-----BEGIN`、OpenAI/LLM API Key `sk-...`、データベース接続文字列 `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`、JWT Token | Critical |

---

## 使用説明

ゼロ設定で使用可能です:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

完全な API リファレンス（インストール、選択的スキャン、カスタム設定、重大度表示、性能）は [API リファレンス](./API.md) を参照してください。

---

## 開発

```bash
# ビルド
cargo build --release

# テスト（46 個の統合テスト）
cargo test

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
