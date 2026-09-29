<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../../README.md)**

Rust로 작성된 공격 탐지 라이브러리로, 인젝션 공격, 프로토콜 공격, 데이터/직렬화 공격, 파일/민감 데이터 유출 등 4개 대분류에 걸친 총 32개의 탐지기를 제공한다. 여기에 더해 세션 보안(`session`), 속도 제한 및 계정 차단(`throttle`), 위험 스코어링(`score`) 3개 모듈을 공개한다. 외부 프레임워크 의존성이 없으며, 의존 크레이트는 `regex` 하나뿐이다.

프로젝트 펫 **甲哨 Sentri**([`pet.svg`](../../pet.svg)) —— 32장의 갑판이 32개 탐지기에 대응한다. 보고만 하고, 차단하지 않는다.

---

## 프로젝트 펫: 甲哨 Sentri

<img src="../../pet.svg" alt="甲哨 Sentri —— security-rust 프로젝트 펫" width="340">

돋보기와 팻말을 든 파수꾼 게. 이 모습은 장식이 아니라 이 라이브러리의 설계를 그대로 그린 것이다:

| 모습 | 대응하는 설계 |
|------|---------|
| 등껍질의 4행 × 8장 갑판 | 32개의 무상태 탐지기. 4행 = 인젝션 / 프로토콜 / 데이터 / 파일 4대 분류 |
| 왼쪽 집게의 돋보기 | **보는** 역할 —— `Detector::detect()`는 스캔만 하고, 적중하면 증거 하나를 반환한다 |
| 오른쪽 집게의 팻말(`已上报` —— "보고 완료") | **보고하는** 역할 —— `DetectionResult`를 반환하며, 예외를 던지지도, 호출 체인을 끊지도 않는다 |
| 집게는 절대 집지 않는다 | 판정권은 호출자에게 있다. 유일한 예외는 `SessionGuard`로, 이것은 정말로 `Block`한다 |
| 외알 안경 | 감사자의 직업병 —— 모든 결론에 `matched_pattern`과 `offset`이 붙어 원문 위치까지 되짚을 수 있다 |
| 명판의 `deps: regex ×1` | 제로 의존성 약속 —— `[dependencies]`는 언제나 `regex` 하나뿐이다 |

좌우명: **보고만 하고, 차단하지 않는다.**

이 모습은 `include_str!`로 크레이트에 포함된다(런타임 비용 제로, 쓰지 않으면 링크되지 않는다). ASCII 버전은 터미널이나 로그에 그대로 출력할 수 있다:

```rust
println!("{}", security_rust::pet::ASCII);
```

---

## 프로젝트 구조

```
security-rust/
├── src/
│   ├── lib.rs              Detector trait(유일한 계약), regex_detect 헬퍼, 크레이트 문서
│   ├── scanner.rs          Scanner / ScannerBuilder: 기본으로 32개 탐지기를 장착
│   ├── result.rs           DetectionResult / AttackCategory / Severity
│   ├── score.rs            위험 스코어링: 가중 합산 + 등급 구분 → RiskAssessment
│   ├── pet.rs              프로젝트 펫(NAME / TAGLINE / ASCII / SVG)
│   ├── injection/          인젝션 탐지기 11개
│   ├── protocol/           프로토콜 탐지기 11개
│   ├── data/               데이터 탐지기 7개
│   ├── file/               파일 탐지기 3개
│   ├── session/            SessionGuard + SessionStore(guard / store / geo)
│   └── throttle/           Throttle + ThrottleStore(guard / store)
├── tests/                  통합 테스트 7개 스위트: 세션, 속도 제한, 라이프사이클, 불변식, 견고성, 엔드투엔드, 다차원 속도 제한
├── examples/
│   ├── waf.rs              엔드투엔드 파이프라인 예제(스캔 → 속도 제한 → 세션 → 처리)
│   └── axum_middleware.rs  axum 미들웨어 연동 레퍼런스
├── docs/
│   ├── API.md              전체 API 참조
│   ├── OWASP-COVERAGE.md   OWASP 공격 분류별 커버리지 대조표
│   ├── pet.svg             프로젝트 펫 이미지
│   ├── diagrams/           아키텍처 / 기능 / 라이프사이클 3개 다이어그램(SVG)
│   ├── i18n/               12개 언어 README와 API 문서
│   └── ...                 후원 QR 코드, 코드 리뷰 및 테스트 보고서
└── Cargo.toml              유일한 런타임 의존성: regex
```

---

## 설계 방향

### 왜 '차단'이 아닌 '탐지'인가

이 라이브러리의 탐지기는 **순수 입력 스캐너**로 설계되었다. 문자열을 받아 구조화된 탐지 결과를 반환한다. 어떤 웹 프레임워크에도 묶이지 않으며, HTTP 요청/응답 파싱을 하지 않고, 실시간 차단도 구현하지 않는다. 따라서 WAF 규칙 엔진, 로그 감사, API 게이트웨이 사전 검증, CLI 보안 스캔 도구 등 어떤 파이프라인에도 끼워 넣을 수 있다.

`session`과 `throttle`은 이 예외로, 상태와 식별 정보를 다룬다. 두 모듈은 의도적으로 `Detector` trait을 구현하지 않는다 —— "token + 핑거프린트 + 위치 + 시각"이라는 복합 입력은 단일 문자열을 받는 `Detector::detect(&str)`로 표현할 수 없기 때문이다.

### 아키텍처 원칙

- **단일 책임** — 각 탐지기는 한 가지 공격 유형만 담당하며, 내부에 컴파일된 정규식 패턴 집합을 보유한다
- **통일된 인터페이스** — `Detector` trait은 모든 탐지기의 유일한 계약이다: `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **기본 제공** — `Scanner::default()` 한 번으로 전체 32개 탐지기를 장착하며, 설정 없이 바로 사용할 수 있다
- **선택적 구성** — `Scanner::builder()`로 필요에 따라 `.with_detector()`를 통해 탐지기를 선택적으로 장착할 수 있다
- **상태 보유 모듈의 분리** — `session` / `throttle`은 의도적으로 `Detector` trait을 구현하지 않는다. 상태를 가지며 식별 정보에 의존하므로 `detect()`의 계약으로 표현할 수 없다. 저장소는 trait(`SessionStore` / `ThrottleStore`)으로 추상화하며, 다중 인스턴스 배포에서는 이를 구현해 Redis 등에 연결한다

### 트레이드오프

| 결정 | 선택 | 이유 |
|------|------|------|
| 정규식 vs 파서 | 정규식 | 탐지 시나리오에서 속도가 우선이며, 정규식은 변형/우회 패턴 커버리지가 더 좋다 |
| 선착순 보고 vs 전체 탐지 | 전체 탐지 | 하나의 입력이 동시에 여러 공격을 유발할 수 있으므로 누락해서는 안 된다 |
| 제로 의존성 vs serde 도입 | 제로 의존성 | 의존 크레이트는 `regex` 하나뿐이라 컴파일이 빠르고 크기가 작다 |
| 제로 의존성 vs 편의성 | 제로 의존성 | token과 서명은 호출자가 준비하고, 위치 정보(위도/경도)도 호출자가 파싱한다. 대신 의존성 추가도, 암묵적 I/O도 없다 |
| fail-closed vs 가용성 | 용도에 따라 분리 | `SessionGuard`는 저장소 장애 시 `Decision::Block`을 반환한다(fail-closed, 절대 통과시키지 않음). `Throttle`은 `ThrottleDecision::Unavailable`을 반환해 판단을 호출자에게 넘긴다 —— 전체 사용자를 막는 것은 자기 DoS이며, 속도 제한은 주된 인증 게이트가 아니기 때문이다 |

### 2단계 판정: 강한 신호와 약한 신호

탐지기는 **"적중하면 선언된 심각도로 보고한다"가 아닙니다**. 32개 탐지기 중 18개가 패턴을 두 단계로 나눕니다(소스의 `STRONG_PATTERNS` / `WEAK_PATTERNS`):

| 단계 | 판정 기준 | 보고되는 심각도 | 단일 적중이 거부선을 넘는가 |
|------|------|-----------|------------------|
| **강한 신호** | 그 형태 자체가 공격에서만 나올 수 있다 | 탐지기가 선언한 등급 | 넘는다 |
| **약한 신호** | 그 토큰이 "출현"했을 뿐, 정상 콘텐츠에도 널려 있다 | 항상 `Severity::Low`(5점) | **넘지 못한다** |

두 단계는 같은 탐지기, 같은 `attack_type`을 지나며 `severity`만 다릅니다. 약한 신호도 **여전히 탐지됩니다** —— 조용히 누락되지 않습니다: `scan()`에서 보이고 `assess()`에서도 정상적으로 누적됩니다.

호출자에게 미치는 직접적 결과는 이렇습니다: **단일 약한 신호는 거부 사유가 되지 않습니다.** 참조 파이프라인([`examples/waf.rs:166`](../../../examples/waf.rs))의 거부선은 `risk.level >= RiskLevel::High`(40점)인데, 단일 약한 신호는 5점뿐이라 이 분기에 들어가지 않습니다. 약한 신호 뒤의 공격을 보려면 `assess()`가 여러 탐지기의 적중을 겹쳐 만든 점수를 봅니다:

```rust
let scanner = Scanner::default();

// 세 건 모두 약한 신호이고 각각 다른 탐지기에 적중 —— 겹쳐야 승격된다
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
// a.results == 3, a.score == 15(3 × Low) → RiskLevel::Medium
// 그래도 High 미만. 같은 요청에 다른 적중이 더 겹치면 넘는다
```

약한 신호로 내려간 것은 "출현 자체가 정상"인 토큰입니다:

| 약한 신호 | 단독으로 거부할 수 없는 이유 |
|--------|-------------------|
| `<script src=...>`, `<iframe>`, `<link>`, `expression(` | 모든 웹 페이지에 있다 |
| 단일 단계 `../` | 모든 소스 파일에 있는 상대 경로 |
| 행두 `-2`, `+1` | Markdown 목록 항목, 산문의 음수 |
| 맨 `__proto__`(프로토타입 읽기) | 프로토타입 체인을 건드리는 JS라면 어디에나 |
| `${env:}` / `${sys:}` | log4j2의 정당한 설정 문법 |
| `X-Forwarded-Host`, `X-Original-URL` | 리버스 프록시 자신이 붙인다 |
| `Host: 10.244.1.5`, `Host: localhost` | k8s pod 간 호출, 로컬 개발 |
| 맨 `10.0.0.5`, `192.168.1.1`, `127.0.0.1` | `X-Forwarded-For`, `bind 127.0.0.1` |
| `//evil.com` 프로토콜 상대 URL | 소스 주석, 문서 안의 CDN 링크 |
| `information_schema` | PG 오류 로그, SQL 튜토리얼 |

위 표는 예시일 뿐입니다. 판정 기준은 **형태**이지 파일 이름이 아닙니다: 같은 `../`라도 단일 단계 `../x`는 약한 신호, 다단계 `../../`는 강한 신호입니다([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). 전체 목록은 각 탐지기의 `WEAK_PATTERNS`와 아래 각 표의 `약` 표시를 참고하십시오.

---

## 설계 아키텍처

<img src="../../diagrams/architecture.svg" alt="security-rust 아키텍처: 호출자 → 탐지 계층 → 스코어링 계층 → 가드 계층 → 저장소" width="900">

5개 계층을 위에서 아래로: **호출자**(WAF / 게이트웨이 / 감사 / CLI) → **탐지 계층**(`Scanner`가 `Vec<Box<dyn Detector>>`를 보유, 4대 분류 총 32개) → **스코어링 계층**(`score::assess`) → **가드 계층**(`SessionGuard` / `Throttle`, 각각 하나의 store trait에 묶인다) → **저장소 추상화**(내장 `MemoryStore`, Redis는 호출자가 구현).
*(다이어그램 주석은 중국어이며, 레이블은 API 이름이다.)*

`Detector` trait은 탐지 계층의 유일한 계약이다: `fn detect(&self, input: &str) -> Option<DetectionResult>`. `session`, `throttle`, `score`는 이를 구현하지 않는다 —— 입력이 단일 문자열이 아니거나(token + 핑거프린트 + 위치 + 시각), 원본 입력이 아니라 스캔 결과를 소비하기 때문에 각자 독립적으로 답한다(아래 참조). 그림 오른쪽의 붉은 반환선이 이 라이브러리의 경계다: **판정 결과는 호출자에게 돌아가 실행되며**, 라이브러리 자신은 요청을 건드리지 않는다.

### 모듈 역할

| 모듈 | 경로 | 탐지기 수 | 역할 |
|------|------|---------|------|
| 핵심 | `src/lib.rs` `result.rs` `scanner.rs` | — | `Detector` trait, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| 인젝션 | `src/injection/` | 11 | XSS, SQL 인젝션, 커맨드 인젝션, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, 포맷 스트링 |
| 프로토콜 | `src/protocol/` | 11 | SSRF, XXE, 헤더 인젝션(CRLF 포함), Host 헤더 공격, 요청 스머글링, 오픈 리다이렉트, CORS, WebSocket, DNS 리바인딩, Log4Shell, HTTP 파라미터 폴루션 |
| 데이터 | `src/data/` | 7 | PHP 역직렬화, CSV 인젝션, 스프레드시트 수식 인젝션, 메일 헤더 인젝션, JWT 공격, 프로토타입 폴루션, ReDoS |
| 파일 | `src/file/` | 3 | 경로 탐색, 악성 파일 업로드, 민감 데이터 유출 |
| 세션 | `src/session/` | — | `SessionGuard`, `RequestContext`, `SessionVerdict`, `SessionStore`/`MemoryStore` —— 클라이언트 탈취, 데이터 변조, 불가능한 이동, token 폐기 판정 |
| 속도 제한 | `src/throttle/` | — | `Throttle`(`check`/`check_any`/`record_failure`/`record_success`/`reset`/`purge_expired`), `ThrottleDecision`, `ThrottleOutcome`, `ThrottleStore`/`MemoryThrottleStore` —— 슬라이딩 윈도, 임계치 차단, 계정 잠금 |
| 스코어링 | `src/score.rs` | — | `RiskLevel`, `RiskAssessment`, `Scanner::assess()` —— 저위험 신호를 집계해 관측 가능한 위험 값으로 만든다 |

### 탐지 결과 구조

`DetectionResult`는 `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message` 6개 필드를 구조화하여 반환한다. 전체 정의는 [API 참조](./API.md)를 참고하라.

---

## 구현 기능

<img src="../../diagrams/features.svg" alt="security-rust 기능도: 인젝션 11, 프로토콜 11, 데이터 7, 파일 3, 그리고 상태를 가진 3개 모듈" width="900">

32개 탐지기는 4대 분류별로 장착되며 `Scanner::default()`로 설정 없이 전부 활성화된다. 아래 표는 각 탐지기가 커버하는 공격 패턴과 심각도를 나열한다. 심각도는 단일 적중의 위험만 나타내며, 집계된 전체 위험은 `Scanner::assess()`를 본다.
*(다이어그램 주석은 중국어이며, 레이블은 API 이름이다.)*

표에서 `약`이 붙은 패턴은 **약한 신호**로, `Severity::Low`(5점)를 보고하며 단독으로는 거부선을 넘지 못한다(앞 절 참고). "심각도" 열은 그 탐지기가 도달할 수 있는 **상한**이다. `약`이 붙은 탐지기는 강한 단계와 약한 단계를 함께 가지며, 위쪽 절반은 여전히 선언된 등급을 보고한다. 전 단계가 약한 탐지기(`dns_rebinding`)의 상한은 `Low`다.

### 인젝션 공격 (11개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **xss** | `onerror=`/`onload=` 등 이벤트 핸들러 전체, `javascript:`/`vbscript:` 의사 프로토콜(scheme 바로 뒤에 비공백이 오는 형태만); `약`: `<script src=...>`/`<iframe>`/`<embed>`/`<object>`/`<link>` 태그, CSS `expression(` | Critical |
| **sql_injection** | `UNION SELECT`, `sleep()`/`benchmark()`/`pg_sleep()` 지연 인젝션(문장 위치에 한정), `exec sp_`/`xp_` 저장 프로시저, 불리언 블라인드 패턴 `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE`, `DROP TABLE`/`INSERT INTO`, 주석 분할 `UN/**/ION`; `약`: `information_schema`라는 단어의 출현 | Critical |
| **command_injection** | `/dev/tcp` 리버스 셸, `passthru()`/`shell_exec()`/`system("…")`/`popen()`/`pcntl_exec()` 호출 형태, `powershell -Command`/`cmd.exe /c` 호출 형태; `약`: 백틱 span, `$()` 서브셸, 파이프/`\|\|`/`&&` 연쇄 실행, `exec(`, `>/dev/null`, `cat /etc/passwd` 같은 reader+경로, 맨 `cmd.exe`/`powershell` 단어 | Critical |
| **nosql_injection** | MongoDB `$ne`/`$gt`/`$regex`/`$where` 연산자, `$or` 인젝션, 인증 우회 `{"$gt": ""}` | Critical |
| **ldap_injection** | `(&` `(\|` `(!` 필터 연산자, `*(cn=` 속성 열거, `objectClass`/`uid` 인젝션 | High |
| **xpath_injection** | `' or '1'='1` 불리언 우회, `' or true()` 함수 인젝션, `'] \| '` 노드 순회 | High |
| **jndi_injection** | `${jndi:` 조회 본체, `${lower:j}`/`${upper:j}` 대소문자 접기, `${::-j}` 빈 문자열 접기(`jndi`를 난독화하기 위해서만 존재); `약`: `${env:}`/`${sys:}`/`${java:}` 정당한 lookup 문법 | Critical |
| **ssi_injection** | `<!--#exec cmd=` 명령 실행, 절대 경로나 `..`를 동반한 `<!--#include file=`, `<!--#printenv` 환경 변수 출력; `약`: `<!--#echo var=` 변수 출력, `<!--#fsize`/`<!--#flastmod` 파일 정보, `<!--#config`, `<!--#include file="header.html"` 같은 통상적 포함 | High |
| **graphql_injection** | 선택 집합을 동반한 `__schema {`/`__type {` 인트로스펙션 쿼리(산문에서 필드 이름을 언급한 것만으로는 보고하지 않음); `약`: `__typename`(Apollo/Relay가 모든 쿼리에 자동으로 넣는다), 5단계 이상의 중첩 중괄호 | Medium |
| **ssti** | Jinja2 `{{ }}` / FreeMarker `${ }` **구분자 내부의 평가**(`{{7*7}}`, `${7*7}`, `{{config`, `${T(java.lang.Runtime)}`, `${@Type@method}`), `{% include '/…'` / `..`를 통한 템플릿 LFI, 구분자 내부의 이스케이프 체인 `__mro__`/`__subclasses__()`/`__globals__`/`__builtins__`/`__class__`/`__dict__`, FreeMarker `?new(`; `약`: `{% %}`, `<%=`/`<%@`, `#set(` 등 맨 템플릿 지시자, 맨 매직 속성. 구분자 자체는 신호가 아니므로 `${x}` 같은 단순 플레이스홀더는 보고하지 않는다 | Critical |
| **format_string** | `%n`/`%hn`/`%lln` 메모리 쓰기 변환자, `%99999999d` 너비 폭탄, 연속 `%x%x%x`·구분자 포함 `%08x.%08x.%08x.%08x` 스택 읽기, 연속 `%s` | Medium |

### 프로토콜 및 요청 공격 (11개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **ssrf** | `169.254.169.254` 클라우드 메타데이터와 `metadata.google.internal`(URL 문맥을 요구하지 않음), **URL authority 위치**(`//` 뒤)의 사설 IP `10.x`/`172.16-31.x`/`192.168.x`/`127.x`, `//localhost`, `//0.0.0.0`, `//[::1]`, 위험 프로토콜 `gopher://`/`dict://`/`ftp://user@`/`file:///`; `약`: **URL이 아닌 위치**의 같은 사설 리터럴(`X-Forwarded-For: 10.0.0.5`, `bind 127.0.0.1`, `{"host": "10.0.0.1"}`은 바이트 단위로 동형) | Critical |
| **xxe** | `<!ENTITY` 엔티티 선언, `SYSTEM`/`PUBLIC` 외부 참조, `%` 파라미터 엔티티, `<!DOCTYPE` DTD 선언 | Critical |
| **header_injection** | 응답 전용 헤더 앞의 `\r\n`: `Set-Cookie`/`Location`/`Refresh`/`Status`/`WWW-Authenticate`, `%0d`와 `%0a`의 동시 출현(역순 `%0a…%0d` 포함). `Content-Length`/`Content-Type`/`Transfer-Encoding`은 **요청** 헤더로, 정상 메시지의 모든 헤더와 바이트 단위로 동형이므로 더 이상 신호가 아니다(인코딩 형태 `%0d%0aContent-Length:`는 여전히 `%0d`+`%0a`가 잡는다) | High |
| **host_header** | **두 개**의 `Host:` 헤더(RFC 7230 §5.4는 일괄 400을 요구한다. 두 계층 파서의 해석이 갈린다); `약`: `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL` —— 프록시 자신도 붙이는 헤더로, 클라이언트 위조와 바이트 단위로 같다(`X-Forwarded-For`/`X-Forwarded-Proto`는 보고하지 않는다) | High |
| **request_smuggling** | 이중 `Transfer-Encoding` 헤더, `Content-Length: 0` 스머글링, `\r\n0\r\n` chunked 종료 난독화 | High |
| **open_redirect** | `javascript:`/`data:text/html`/`data:text/plain` 의사 프로토콜 점프(scheme 뒤에 내용을 요구); `약`: `//evil.com` 프로토콜 상대 URL —— 소스 주석과 문서 안의 CDN 링크와 동형 | Medium |
| **cors** | `Access-Control-Allow-Origin: null`, 그리고 `Access-Control-Allow-Origin: *`와 `Access-Control-Allow-Credentials: true`의 **동시 출현**; `약`: 요청 측 `Origin: null`(샌드박스 iframe, `data:` URL, 로컬 파일의 오리진이 `null`이며, 서버가 `ACAO: null`로 되돌려줘야 성립한다). 단독으로는 공개 API와 정적 자산에서 정상이므로 보고하지 않는다 | Medium |
| **websocket** | `Origin: null` 과 WebSocket 업그레이드의 동시 출현(CSWSH), `ws://` 가 루프백/사설/링크 로컬 주소를 가리키는 경우(클라우드 메타데이터 엔드포인트 `169.254.169.254` 포함) | High |
| **dns_rebinding** | Host 헤더가 `127.x`/`10.x`/`192.168.x`/`172.16-31.x` 사설 IP, `localhost`, `[::1]`, `0.0.0.0`인 경우. **탐지기 전체가 약한 단계뿐이다**: 일괄 `Low`를 보고한다("알려진 한계" 참고) | Low |
| **log4shell** | `${lower:j}`/`${upper:J}` 대소문자 접기, `${::-j}` 접두사 접기, lookup 전개 후 `ndi:`가 나타나는 난독화, `${${...}}` 중첩 전개, URL 인코딩 형태 `%24%7b...%7d` | Critical |
| **hpp** | `&`와 `;` 구분자 혼용(`?a=1&b=2;c=3`, 두 계층 파서가 서로 다른 파라미터 개수를 낸다); `약`: 같은 이름 파라미터의 중복(`?id=1&id=2`) —— 정상적인 다중값 파라미터 `?tag=rust&tag=web`과 바이트 단위로 같다; `;jsessionid=` 행렬 파라미터는 경로 구분자이므로 제외 | Medium |

### 데이터 및 직렬화 공격 (7개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **deserialization** | PHP `O:숫자:`/`C:숫자:` 직렬화 객체, `a:숫자:{` 배열, `unserialize()` 호출, 매직 메서드의 **호출 형태**(`__wakeup(`/`__destruct(`/`__construct(`/`__toString(`/`__get(`/`__set(`/`__call(`); `약`: 맨 매직 메서드 이름(이들을 설명하는 문서에서도 똑같이 적중한다) | Critical |
| **csv_injection** | 구분자 `,`/`;`/`\t` 직후에 비공백이 이어지는 `=`(TSV/CSV 두 번째 셀의 수식), 행두 `DDE`, 행두 `cmd\|` 명령 파이프, 행두 `@SUM(`; `약`: 행두 `=`/`+`/`-`이면서 그 뒤가 공백도 동족 기호도 아닌 것(`- item` 목록 항목, `---` 구분선, `++i`, `= 5`는 모두 적중하지 않는다). `@`는 거친 단계에서 전면 제외했다(`@media`/`@import`는 스타일시트에 널려 있다) —— `@SUM(`만 남긴다. 탭과 캐리지 리턴은 **구분자**이며 수식 시작이 아니다 | Medium |
| **mail_header** | 인접한 두 개의 `From:` 헤더, 행두 `MIME-Version:`(HTTP 필드 표에 없는 이름); `약`: 행두 `Cc:`/`Bcc:` —— 전달 메일이나 상담 시스템이 수집한 수신 메일 본문과 바이트 단위로 동형. `Content-Type: multipart`와 `boundary=`는 **삭제했다**(`Content-Type: multipart/form-data`는 모든 파일 업로드 POST의 표준 헤더다). 상한은 Medium(15점)이며 **단독으로는 거부선을 넘지 못한다** | Medium |
| **jwt_attack** | `alg: none` 빈 알고리즘 우회, `kid` 경로 탐색 인젝션, 빈 서명 세그먼트, 빈 payload 세그먼트 | High |
| **prototype_pollution** | `__proto__`가 키이거나 대입 대상인 경우(`"__proto__":`, `[__proto__]`, `__proto__ = x`), `constructor.prototype`/`constructor[`, `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__`, `hasOwnProperty[`; `약`: 맨 `__proto__`(`obj.__proto__`로 프로토타입을 읽는 것은 언어 자체의 표기다) | High |
| **formula_injection** | 셀 선두의 `=cmd` + 파이프(명령 실행), `HYPERLINK()`/`IMPORTXML()`/`WEBSERVICE()`/`RTD()` 등 데이터 유출·로컬 실행 함수, DDE 셀 참조(`!A0`), `DDE(` 페이로드, `@SUM(` 등 구식 `@` 수식 —— CSV의 거친 층과 달리 실행·유출 가능한 페이로드만 잡는 정밀 층 | High |
| **redos** | `(a+)+`/`(a*)*`처럼 수량자가 중첩된 형태, `(a+){2,}`, `\d`와 `\w`처럼 겹치는 문자 클래스 분기, `(x\|)` 빈 분기, 첫 분기가 단일 문자이고 접두사가 겹치는 `(a\|ab)*` —— 지수적 백트래킹을 일으키는 정규식 | Medium |

### 파일 및 민감 데이터 (3개 탐지기)

| 탐지기 | 커버 패턴 | 심각도 |
|--------|---------|--------|
| **path_traversal** | **다단계** 상향 이동 `(?:\.\./){2,}`/`(?:\.\.\\){2,}`, `%2e%2e`/`..%2f`/`..%5c` URL 인코딩 우회, `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://` 프로토콜 래퍼, `%00` 널 바이트 종료; `약`: 단일 단계 `../`/`..\`(모든 소스에 있는 상대 경로와 동형) | Critical |
| **upload** | `<?php`/`<?=` PHP 태그, `<%@`/`<%=` ASP 태그, `eval($_`/`system($_`/`exec($_`/`passthru($_` 백도어 패턴, `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER` 슈퍼글로벌, `base64_decode()` 인코딩 우회 | Critical |
| **data_leak** | 16자리 신용카드 PAN(Visa/MasterCard/AmEx/Discover/JCB/Diners), AWS Access Key `AKIA...`, PEM 개인키 헤더 `-----BEGIN`, OpenAI/LLM API Key `sk-...`, DB 연결 문자열 `mongodb://`/`mysql://`/`postgresql://`/`redis://`(**`@`가 있는 userinfo 필수**: `mysql://root:secret@db`는 보고하고, `redis://shared-memory`, `postgres://localhost:5432/app` 같은 설정 관행은 **보고하지 않는다**), `jdbc:`(이 제약 없음), JWT 토큰 | Critical |

---

## 알려진 한계

다음은 **알려져 있고 의도적으로 남긴** 경계이며, 고쳐야 할 결함이 아니다. 바꾸기 전에 근거를 읽어 보라 —— 모두 실측에서 나왔고, 누군가 더 조이려다 같은 벽에 부딪힌 것들이다.

### `dns_rebinding`은 보고만 하고 막지 않는다

판정 기준은 "`Host:` 헤더에 사설 주소가 나타난다"인데, 같은 형태가 k8s의 모든 pod 간 호출(`Host: 10.244.1.5:8080`), 모든 로컬 개발(`Host: localhost:8000`), 모든 Docker 컨테이너 네트워크 요청(`172.18.0.2`)이기도 하다. 진짜 rebinding이 보는 것은 "공인 도메인 이름 + 해석 결과가 내부를 향함"이고, 브라우저가 보내는 `Host`는 바로 그 공인 도메인 이름이다 —— **단일 문자열에서는 해석 이력이 보이지 않는다**. 그래서 이 탐지기가 재는 형태는 공격 형태와 겹치지 않으며 조일 방향이 없다. 따라서 탐지기 전체가 약한 단계뿐이고 일괄 `Low`를 보고하며, 아무리 많이 겹쳐도 단독으로는 거부선을 넘지 않는다. 방어는 해석 **이후**에 결과 IP를 대조하는 곳에 있고 문자열 계층에는 없다.

### 이 라이브러리는 자기 소스·테스트·문서를 스캔할 수 없다

시그니처 스캐너의 천장: 실측으로 이 저장소의 298개 파일 중 78개가 거부선을 넘는데, 그 모두가 **구조상** 공격 문자열을 담고 있다 —— 테스트 페이로드, 탐지기 소스 자체의 정규식 리터럴, 그리고 이 패턴들을 나열하는 README와 OWASP 표다. README는 `(a+)+`를 적었다고 해서 결함이 되지 않는다. 자기 산출물을 스캔하려면 먼저 이 코퍼스를 제외하거나 다른 판정 기준으로 바꿔야 한다.

### `upload`는 `<%@` / `<?php`를 일괄 Critical로 보고한다

이 탐지기의 계약은 "**이 blob은 서버 측에서 실행 가능한 코드다**" —— 출현 자체로 성립하므로 강약 계층을 두지 않는다. JSP 페이지와 JSP 웹셸의 선두 바이트는 바이트 단위로 같고(`<%@ page language="java" … %>`와 `<%@ page import="java.io.*" %>`는 같은 형태다), `<%@`/`<%=`를 강등하는 것은 웹셸을 거부선 아래로 떨어뜨리는 일 —— 다른 방식으로 탐지를 지우는 것과 같다. 대가는 **현재 서비스 중인** 페이지(업로드된 파일이 아니라)를 스캔해도 적중한다는 것인데, 그것은 입력 영역의 불일치다 —— 적중 메시지 `Malicious file upload detected`가 그 영역을 밝히고 있다.

### `path_traversal`은 `(?:\.\./){2,}`를 Critical로 보고한다

monorepo의 깊은 상대 경로(`from '../../../shared/domain'`)가 적중한다. 더 조이지 않은 이유는, 공격과 구분할 수 있는 유일한 제약이 대상 파일 이름 목록(`../etc/passwd` 류)인데 그것이 시스템 파일만 덮기 때문이다 —— 공격자는 LFI 대상을 바꾸면 빠져나간다.

---

## 라이프사이클

<img src="../../diagrams/lifecycle.svg" alt="security-rust의 3가지 라이프사이클: 스캔, 세션, 속도 제한" width="900">

세 라이프사이클은 서로 독립적이며, 유일한 교차점은 호출자의 요청 처리 함수다:

| 라이프사이클 | 시작 | 끝 | 상태 저장 위치 |
|---------|------|------|---------|
| **스캔** | `Scanner::scan(&str)` | `Vec<DetectionResult>` → `score::assess` → `RiskAssessment` | 무상태, 호출마다 독립 |
| **세션** | `SessionGuard::bind()`가 `SessionRecord`를 기록 | 요청마다 `verify()` → `SessionVerdict` ⇒ `Allow` / `Challenge` / `Block` | `SessionStore`(내장 `MemoryStore`) |
| **속도 제한** | `Throttle::check_any(&[keys])` | `Allow{remaining}` / `Banned{until}` / `Unavailable` | `ThrottleStore`(내장 `MemoryThrottleStore`) |

쉽게 틀리는 두 경계:

- **`remaining == 0`은 이 요청을 거부해야 한다는 뜻이다** —— 할당량이 소진된 것이지 "한 번 더 시도할 수 있다"는 뜻이 아니다. `X-RateLimit-*`에 쓸 때 반대로 쓰지 말 것.
- **저장소 장애 처리는 양쪽이 반대다**: `SessionGuard`는 fail-closed(`StoreUnavailable` ⇒ `Block`, 절대 통과시키지 않는다. 그렇지 않으면 공격자가 장애를 유도하는 것만으로 판정 한 종류를 통째로 바꿀 수 있다), `Throttle`은 fail-open(`Unavailable`을 호출자에게 넘긴다. 백엔드가 흔들릴 때 전체 사용자를 막는 것은 자기 DoS이며, 주 게이트인 `SessionGuard`가 여전히 막고 있다). 이는 설계로 못 박은 것이지 빠뜨린 안전장치가 아니다.

---

## 사용 방법

설정 없이 바로 사용할 수 있다:

```rust
use security_rust::Scanner;

let scanner = Scanner::default();

// 강한 신호: 형태 자체가 공격에서만 나올 수 있다 ⇒ 탐지기가 선언한 심각도로 보고
let results = scanner.scan("<img src=x onerror=alert(1)>");
// [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

// 약한 신호: 토큰이 출현했을 뿐 ⇒ 항상 Low, 단독으로는 거부선을 넘지 못한다("2단계 판정" 참고)
let weak = scanner.scan("<script src=\"/app.js\"></script>");
// [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
```

위험 스코어링은 적중 목록을 하나의 등급으로 모아, 여러 저위험 신호가 조용히 무시되지 않게 한다:

```rust
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");
// assessment.level   >= RiskLevel::High
// assessment.results >= 3
// assessment.score   — 원시 가중 점수
```

전체 API 참조(설치, 선택적 스캔, 커스텀 구성, 위험 스코어링, 심각도 표시, 세션 보안, 속도 제한과 차단, 성능)는 [API 참조](./API.md)를 참고하라.

### 세션 보안 (`session`)

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

let login = RequestContext {
    token: "tok-abc",
    subject: "u-1",
    fingerprint: "ip=1.2.3.4|ua=curl",   // 클라이언트 핑거프린트. 로그인 시 바인딩
    location: Some("CN-BJ"),
    coords: Some((39.9042, 116.4074)),
    signature: None,                      // MAC은 호출자가 서명한다
    at: None,
};

// 로그인: 세션 생성 + 핑거프린트 바인딩 + 위치 기록. 다른 지역은 verdict에만 영향하고 로그인을 막지 않는다
guard.bind(&login, 1_700_000_000).unwrap();

// 요청마다 검증: 같은 token인데 핑거프린트가 다르면 ⇒ 클라이언트 탈취
let verdict = guard.verify(&RequestContext { fingerprint: "ip=5.6.7.8|ua=curl", ..login }, 1_700_000_010);

match verdict.decision {
    Decision::Allow => { /* 통과 */ }
    Decision::Challenge => { /* 통과하되 2차 검증 요구: 다른 지역, 시계 오차, 서명 불일치 */ }
    Decision::Block => { /* 거부 */ }
}
```

### 속도 제한과 차단 (`throttle`)

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
let key = "acct:u-1"; // key는 호출자가 만들고 정규화한다. 원본 입력을 그대로 key로 쓰지 말 것
let now = 1_700_000_000;

// 실제 요청에는 IP와 계정 두 차원이 있다. check_any가 한 번에 질의하고 엄격도 순으로 병합한다
match throttle.check_any(&["ip:1.2.3.4", key], now) {
    // remaining은 X-RateLimit-*에 실을 수 있다. **remaining == 0은 이 요청을 거부해야 한다는 뜻**
    ThrottleDecision::Allow { remaining } => { /* 남은 할당량 remaining */ }
    // now >= until이면 해제된 것으로 본다
    ThrottleDecision::Banned { until } => { /* 차단 중, until에 해제 */ }
    // 백엔드 장애: 이 모듈은 호출자 대신 결정하지 않는다(통과 + 경고 권장)
    ThrottleDecision::Unavailable => { /* 속도 제한 백엔드 사용 불가 */ }
}

// 인증 실패를 기록: threshold에 도달하면 차단. 반환은 ThrottleOutcome(2가지 상태)이고,
// 저장소 장애는 Err로 간다 —— 결코 실행되지 않을 Unavailable 분기를 위해 코드를 쓰지 않아도 된다
let _ = throttle.record_failure(key, now);
```

---

## 개발

```bash
# 빌드
cargo build --release

# 테스트(580개: 유닛 431 + 통합 148 + 문서 테스트 1)
cargo test

# 엔드투엔드 파이프라인 예제(스캔 → 속도 제한 → 세션 → 처리)
cargo run --example waf

# 코드 검사
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
