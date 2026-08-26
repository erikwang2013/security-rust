<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Rust로 작성된 공격 탐지 라이브러리로, 인젝션 공격, 프로토콜 공격, 데이터/직렬화 공격, 파일/민감 데이터 유출 등 4개 대분류에 걸친 총 27개의 탐지기를 제공한다. 외부 프레임워크 의존성이 없으며, 순수 문자열 스캔만 수행한다.

---

## 설계 방향

### 왜 '차단'이 아닌 '탐지'인가

이 라이브러리는 **순수 입력 스캐너**로 설계되었다. 문자열을 받아 구조화된 탐지 결과를 반환한다. 어떤 웹 프레임워크에도 묶이지 않으며, HTTP 요청/응답 파싱을 하지 않고, 실시간 차단도 구현하지 않는다. 따라서 WAF 규칙 엔진, 로그 감사, API 게이트웨이 사전 검증, CLI 보안 스캔 도구 등 어떤 파이프라인에도 끼워 넣을 수 있다.

### 아키텍처 원칙

- **단일 책임** — 각 탐지기는 한 가지 공격 유형만 담당하며, 내부에 컴파일된 정규식 패턴 집합을 보유한다
- **통일된 인터페이스** — `Detector` trait은 모든 탐지기의 유일한 계약이다: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **기본 제공** — `Scanner::default()` 한 번으로 전체 27개 탐지기를 장착하며, 설정 없이 바로 사용할 수 있다
- **선택적 구성** — `Scanner::builder()`로 필요에 따라 `.with_detector()`를 통해 탐지기를 선택적으로 장착할 수 있다

### 트레이드오프

| 결정 | 선택 | 이유 |
|------|------|------|
| 정규식 vs 파서 | 정규식 | 탐지 시나리오에서 속도가 우선이며, 정규식은 변형/우회 패턴 커버리지가 더 좋다 |
| 선착순 보고 vs 전체 탐지 | 전체 탐지 | 하나의 입력이 동시에 여러 공격을 유발할 수 있으므로 누락해서는 안 된다 |
| 제로 의존성 vs serde 도입 | 제로 의존성 | `regex` + `thiserror`만 사용하므로 컴파일이 빠르고 크기가 작다 |

---

## 설계 아키텍처

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
  │  10 个  │  │   9 个      │  │ 5 个   │  │  3 个   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

### 모듈 역할

| 모듈 | 경로 | 탐지기 수 | 역할 |
|------|------|---------|------|
| 핵심 | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| 인젝션 | `src/injection/` | 10 | XSS, SQL 인젝션, 커맨드 인젝션, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI |
| 프로토콜 | `src/protocol/` | 9 | SSRF, XXE, 헤더 인젝션, Host 헤더 공격, 요청 스머글링, 오픈 리다이렉트, CORS, WebSocket, DNS 리바인딩 |
| 데이터 | `src/data/` | 5 | PHP 역직렬화, CSV 수식 인젝션, 메일 헤더 인젝션, JWT 공격, 프로토타입 폴루션 |
| 파일 | `src/file/` | 3 | 경로 탐색, 악성 파일 업로드, 민감 데이터 유출 |

### 탐지 결과 구조

`DetectionResult`는 `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message` 6개 필드를 구조화하여 반환한다. 전체 정의는 [API 참조](./API.md)를 참고하라.

---

## 구현 기능

### 인젝션 공격 (10개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **xss** | `<script>`, `onerror=` 등 이벤트 핸들러, `javascript:` 의사 프로토콜, `<svg>`/`<iframe>` 태그, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()` 지연 인젝션, `information_schema` 열거, `exec sp_`/`xp_` 저장 프로시저, 불리언 블라인드 패턴 `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | 백틱 명령, `$()` 서브셸, 파이프 기호 연쇄 실행, `/dev/tcp` 리버스 셸, `passthru()`/`shell_exec()`/`system()` PHP 함수, `cmd.exe`/`powershell` 호출 | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` 연산자, `$or` 인젝션, 인증 우회 `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(|` `(!` 필터 연산자, `*(cn=` 속성 열거, `objectClass`/`uid` 인젝션 | High |
| **xpath_injection** | `' or '1'='1` 불리언 우회, `' or true()` 함수 인젝션, `'] | '` 노드 순회 | High |
| **jndi_injection** | `${jndi:ldap://`, `${lower:j}` 난독화, `${upper:j}` 난독화, `${::-j}` 빈 문자열 난독화, `${env:}` 환경 변수 조회, `${sys:}` 시스템 속성 | Critical |
| **ssi_injection** | `<!--#exec cmd=` 명령 실행, `<!--#include file=` 파일 포함, `<!--#echo var=` 변수 출력, `<!--#fsize`/`<!--#flastmod` 파일 정보 | High |
| **graphql_injection** | `__schema`/`__type` 인트로스펙션 쿼리, 심층 중첩 DoS(5단계 이상) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, Python MRO `__mro__`/`__subclasses__()` 샌드박스 탈출 | Critical |

### 프로토콜 및 요청 공격 (9개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` 클라우드 메타데이터, RFC1918 사설 IP(10.x, 172.16-31.x, 192.168.x), `127.x` 루프백, `::1` IPv6 루프백, `0.0.0.0`, `gopher://`/`dict://`/`ftp://`/`file://` 위험 프로토콜 | Critical |
| **xxe** | `<!ENTITY` 엔티티 선언, `SYSTEM`/`PUBLIC` 외부 참조, `%` 파라미터 엔티티, `<!DOCTYPE` DTD 선언 | Critical |
| **header_injection** | `%0d%0a` URL 인코딩 CRLF, `\r\n` 원본 CRLF 인젝션 | High |
| **host_header** | 다중 Host 헤더 인젝션, `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` 포이즈닝, Host에 딸린 CRLF | High |
| **request_smuggling** | 이중 `Transfer-Encoding` 헤더, `Content-Length: 0` 스머글링, `\r\n0\r\n` chunked 종료 난독화 | High |
| **open_redirect** | `//evil.com` 프로토콜 상대 URL, `javascript:`/`data:text/html` 의사 프로토콜 점프 | Medium |
| **cors** | `Origin: null` 우회, `Access-Control-Allow-Origin: *` + Credentials 조합 | Medium |
| **websocket** | `Upgrade: websocket` 핸드셰이크, `Origin: null` 크로스 도메인 WS, `ws://` 평문 연결 | High |
| **dns_rebinding** | Host 헤더가 `127.x`/`10.x`/`192.168.x`/`172.16-31.x` 사설 IP, `localhost`, `::1`, `0.0.0.0`인 경우 | High |

### 데이터 및 직렬화 공격 (5개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **deserialization** | PHP `O:숫자:`/`C:숫자:` 직렬화 객체, `a:숫자:{` 배열, `unserialize()` 호출, `__wakeup`/`__destruct`/`__toString` 등 매직 메서드 | Critical |
| **csv_injection** | 행 시작 `=`/`+`/`-`/`@` 수식 문자, DDE 동적 데이터 교환, `cmd|` 명령 파이프, `@SUM()` 함수 | Medium |
| **mail_header** | `Bcc:`/`Cc:` 숨은 참조 인젝션, `From:` 다중 발신자, `MIME-Version:`/`Content-Type: multipart` MIME 헤더 인젝션, `boundary=` 경계 조작 | Medium |
| **jwt_attack** | `alg: none` 빈 알고리즘 우회, `kid` 경로 탐색 인젝션, 빈 서명 세그먼트, 빈 payload 세그먼트 | High |
| **prototype_pollution** | `__proto__`/`constructor.prototype` 프로토타입 체인 폴루션, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` 속성 하이재킹 | High |

### 파일 및 민감 데이터 (3개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **path_traversal** | `../`/`..\\` 디렉터리 상향 이동, `%2e%2e` URL 인코딩 우회, `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` 프로토콜 래퍼, `%00` 널 바이트 종료 | Critical |
| **upload** | `<?php`/`<?=` PHP 태그, `<%@`/`<%=` ASP 태그, `eval($_`/`system($_`/`exec($_`/`passthru($_` 백도어 패턴, `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` 슈퍼글로벌, `base64_decode()` 인코딩 우회 | Critical |
| **data_leak** | 16자리 신용카드 PAN(Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, PEM 개인키 헤더 `-----BEGIN`, OpenAI/LLM API Key `sk-...`, DB 연결 문자열 `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, JWT 토큰 | Critical |

---

## 사용 방법

설정 없이 바로 사용할 수 있다:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

전체 API 참조(설치, 선택적 스캔, 커스텀 구성, 심각도 표시, 성능)는 [API 참조](./API.md)를 참고하라.

---

## 개발

```bash
# 构建
cargo build --release

# 测试（46 个集成测试）
cargo test

# 代码检查
cargo clippy -- -D warnings
```

---

## 후원 / 기부

이 프로젝트가 도움이 되었다면 자유롭게 후원해 주시기 바랍니다(자발적).

| 알리페이 | 위챗페이 |
|--------|---------|
| ![알리페이](./alipay.png) | ![위챗페이](./weixinpay.png) |

### 해외 송금 (국제 송금)

【수취인 정보】
- 수취인 이름: WANG KEXUN
- 수취인 계좌 번호: 881015918251

【수취 은행】
- ZA Bank SWIFT Code: AABLHKHHXXX
- 은행 이름: ZA Bank Limited
- 은행 번호: 387
- 은행 주소: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【해외 송금 중계 은행(필요 시)】

주의: 이는 해외 송금 중계 은행(중개 은행) 정보이며, 수취 은행 정보가 아닙니다. 송금 은행에 중계 은행 정보가 필요한지 문의하시기 바랍니다.

홍콩 달러, 위안화, 미국 달러 송금의 중계 은행은 Citibank입니다:
- 은행 이름: Citibank N.A. Hong Kong
- SWIFT Code: CITIHKHXXXX
- 은행 번호: 006
- 지점 이름: Hong Kong Branch
- 지점 번호: 391
- 은행 주소: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

기타 통화 송금의 중계 은행은 BNY Mellon입니다:
- 은행 이름: THE BANK OF NEW YORK MELLON
- SWIFT Code: IRVTUS3NXXX
- 은행 주소: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## 라이선스

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
