<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API 참조

[中文](../../../README.md) | [English](../en/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [한국어 (本页)](./API.md)

---

## 핵심 Trait

### `Detector`

모든 탐지기의 유일한 계약:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — 탐지기 이름 (예: `"xss"`, `"sql_injection"`)
- `detect()` — 입력을 스캔하여 탐지되면 `Some(DetectionResult)` 반환, 미탐지 시 `None` 반환

`session`과 `throttle`은 의도적으로 이 trait을 구현하지 않는다([세션 보안](#세션-보안-session) 참고). 두 모듈은 상태와 식별 정보를 다루며, "token + 핑거프린트 + 위치 + 시각"이라는 복합 입력을 단일 `&str`로 표현할 수 없기 때문이다.

## 탐지 결과 구조

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // 실제로 매칭된 패턴 조각
    pub offset: usize,            // 입력 내 바이트 오프셋
    pub message: String,          // 사람이 읽을 수 있는 설명
}
```

## 2단계 신호: 강한 신호와 약한 신호

32개 탐지기 중 18개가 패턴을 두 단계로 나눈다(소스의 `STRONG_PATTERNS` / `WEAK_PATTERNS`). `DetectionResult`의 필드 구조는 그대로이고, 달라지는 것은 `severity` 값이다:

| 단계 | 판정 기준 | `severity` | 단일 적중이 거부선을 넘는가 |
|------|------|-----------|------------------|
| **강한 신호** | 그 형태 자체가 공격에서만 나올 수 있다 | 탐지기가 선언한 등급 | 넘는다 |
| **약한 신호** | 그 토큰이 "출현"했을 뿐, 정상 콘텐츠에도 널려 있다 | 항상 `Severity::Low`(5점) | **넘지 못한다** |

같은 탐지기, 같은 `attack_type`이며 `severity`만 다르다. `detect()`는 강한 단계를 먼저 시도하고 강한 단계가 맞지 않으면 약한 단계를 시도하므로 **각 탐지기는 최대 한 건만 반환한다**. 약한 신호도 여전히 탐지되며 조용히 누락되지 않는다.

`DetectionResult` 자체는 단계를 구분하지 않는다 —— 어떤 적중이 강한지 약한지는 `severity == Severity::Low`로 알 수 있다(약한 단계가 `Low`를 보고하는 유일한 출처다). 참조 파이프라인의 거부선은 40점(`risk.level >= RiskLevel::High`, [`examples/waf.rs:166`](../../../examples/waf.rs))이고, 단일 약한 신호는 5점뿐이라 이 분기에 들어가지 않는다.

약한 신호 뒤의 공격을 보려면 `assess()`가 여러 탐지기의 적중을 겹친다:

```rust
let scanner = Scanner::default();

// 약한 신호 3건이 서로 다른 탐지기 3개에 적중. 겹쳐야 겨우 Medium(15점)에 도달하지만 High 미만
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

약한 신호로 내려간 형태의 예(전체 목록은 각 탐지기의 `WEAK_PATTERNS`): `<script src=...>`, 단일 단계 `../`, 행두 `-2`, 맨 `__proto__`, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, 맨 `10.0.0.5`, `//evil.com`, `information_schema`.

판정 기준은 **형태**이지 파일 이름이 아니다: 같은 `../`라도 단일 단계 `../x`는 `Low`, 다단계 `../../`는 `Critical`을 보고한다([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). 각 탐지기가 어디까지 도달할 수 있는지는 아래 각 표와 [README](./README.md)의 기능 표를 참고하라.

## Scanner

### 설치

```toml
[dependencies]
security-rust = "3.0.0"
```

### 빠른 시작

```rust
use security_rust::Scanner;

fn main() {
    // 설정 없이 전체 32개 탐지기 장착
    let scanner = Scanner::default();

    // 입력을 스캔하여 탐지된 모든 공격을 반환한다(각 탐지기는 최대 한 건)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 출력:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // 약한 신호는 같은 탐지기, 같은 attack_type을 지나며 severity만 Low가 된다
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
}
```

### 선택적 스캔

```rust
let scanner = Scanner::default();

// 지정한 탐지기만 실행
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### 커스텀 구성

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// builder로 필요한 탐지기만 장착
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### 심각도 표시

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

`Severity` 외의 상태 레이블도 `Display`를 구현하며 모두 대문자로 출력됩니다: `Decision`(`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat`(예: `impossible travel (11205 km/h)`), `AttackCategory`(소문자, 예: `injection`), `ThrottleDecision`(`ALLOW` / `BANNED` / `UNAVAILABLE`), `ThrottleOutcome`(`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## 세션 보안 (`session`)

클라이언트의 세션 탈취, 데이터 변조, 불가능한 이동(짧은 시간 내의 지리적 이동), token 세션 폐기를 판정한다.

```rust
use security_rust::session::{Decision, MemoryStore, RequestContext, SessionConfig, SessionGuard};

let now = 1_700_000_000u64;
let guard = SessionGuard::new(MemoryStore::new(), SessionConfig::default());

// 로그인 시: token에 클라이언트 핑거프린트를 묶는다
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

// 요청마다: 검증하고 판정을 받는다
let verdict = guard.verify(&ctx, now);
match verdict.decision {
    Decision::Allow => {}      // 통과
    Decision::Challenge => {}  // 추가 검증(MFA 등)
    Decision::Block => {}      // 차단
}
```

- `SessionGuard<S: SessionStore>` — `bind` / `verify` / `revoke` / `revoke_all` / `rotate` / `purge_expired`(반환값은 **세션 건수만**이며, 회수된 로그인 이력은 포함하지 않는다)
- `SessionVerdict` — `decision: Decision`(`Allow` / `Challenge` / `Block`), `severity: Option<Severity>`(통과 시 `None`), `threats: Vec<SessionThreat>`
- `SessionConfig` — `ttl_secs`(기본 3600), `impossible_travel_kmh`(기본 900.0), `timestamp_skew_secs`(기본 300)
- `SessionStore` trait과 `MemoryStore`

**fail-closed** — 저장소 장애 시 `SessionThreat::StoreUnavailable`을 동반한 `Decision::Block`을 반환하며, 절대 통과시키지 않는다. 인증 게이트가 fail-open이면 저장소를 죽이는 것만으로 인증을 우회할 수 있기 때문이다.

`token`과 `signature`(MAC)는 호출자가 준비하고, `location` / `coords`도 호출자가 파싱해 넘긴다. 라이브러리 의존성을 `regex` 하나로 유지하기 위해 token 발급도, 서명 검증도, geo 데이터베이스도 갖지 않는다.

`subject`는 **`bind`만 사용하며 `verify`는 완전히 무시한다** — 요청마다 검증되는 신원은 항상 서버 측 `SessionRecord`에서 오고(원격지 이력은 `record.subject`로 집계된다), 호출자가 넘긴 `subject`는 신뢰할 수 없다. 따라서 미들웨어에서 `subject: ""`를 넘기는 것은 정당하다(비어 있지 않은 값을 요구하는 쪽은 `bind`이다). 바로 그렇기 때문에 요청 헤더의 사용자 식별자를 여기에 **절대** 넣어서는 안 된다. 오늘은 판정에 도달하지 않지만, 향후 리팩터링이 그것을 유지할 의무는 없다.

## 속도 제한과 차단 (`throttle`)

슬라이딩 윈도 내 실패 횟수 집계, 임계치 도달 시 차단, 계정 잠금을 담당한다.

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome};

let now = 1_700_000_000u64;
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining } => {
        // X-RateLimit-*에 실어 보낸다. remaining == 0이면 이 요청은 거부해야 한다
    }
    ThrottleDecision::Banned { until } => { /* now >= until이면 해제된 상태 */ }
    ThrottleDecision::Unavailable => { /* 백엔드 장애. 판단은 호출자에게 */ }
}

// 여러 차원을 하나로 합친다(예: IP + 계정). 가장 엄격한 결과가 채택된다
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);  // ThrottleDecision

// 인증 실패·성공을 기록해 윈도를 진행시킨다
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* 저장소 장애 */ }
}
throttle.record_success("acct:user-42")?;
```

- `Throttle<S: ThrottleStore>` — `check` / `check_any` / `record_failure` / `record_success` / `reset` / `purge_expired`
- `ThrottleConfig` — `threshold`(기본 5), `window_secs`(기본 60), `ban_secs`(기본 900)
- `ThrottleStore` trait과 `MemoryThrottleStore`

`Allow { remaining: 0 }`은 "한 번 더 시도 가능"이 아니라 "이 요청은 거부해야 함"을 뜻한다.

**가용성 측의 예외** — 저장소 장애 시 `check` / `check_any`가 `ThrottleDecision::Unavailable`을 반환하며 `Banned`로는 만들지 않는다. 전체 사용자를 막아서는 것은 자기 DoS이고, 속도 제한은 주된 인증 게이트가 아니라 다층 방어이기 때문이다. `SessionGuard`의 fail-closed와 의도적으로 다르다. `Unavailable`은 `check` / `check_any`만 반환하며, `record_failure`는 이 변종이 없는 `ThrottleOutcome`을 반환한다(저장소 장애는 `Err(StoreError)`가 된다). `check_any`는 여러 차원을 합쳐 `Banned`가 있으면 가장 늦은 `until`로 `Banned`, 없으면 `Unavailable`, 없으면 가장 작은 `remaining`으로 `Allow`를 반환하고, 빈 목록은 `Allow { remaining: 0 }`이 된다.

**저장소** — 두 모듈 모두 `SessionStore` / `ThrottleStore` trait으로 백엔드를 추상화한다. 다중 인스턴스 배포에서는 이 trait을 구현해 Redis 등을 끼워 넣으면 된다.

## 위험 스코어링 (`score`)

개별 탐지 결과는 "그 공격이 있었다"는 사실만 말해 준다. `score`는 이를 가중 합산해 관측 가능한 위험 값으로 바꾼다.

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let assessment = scanner.assess("=cmd|' /C calc'!A0 `cat /etc/passwd` ../../../etc/passwd");

println!("{} / {} / {}", assessment.level, assessment.score, assessment.results);
// CRITICAL | HIGH | MEDIUM | LOW | NONE
```

- `RiskLevel` — `None` / `Low` / `Medium` / `High` / `Critical`
- `RiskAssessment` — `level`, `score`(가중치 합), `results`(합산에 참여한 건수)
- `Scanner::assess(&str) -> RiskAssessment`, 그리고 자유 함수 `score::assess(&[DetectionResult])`

가중치는 `Critical`=100, `High`=40, `Medium`=15, `Low`=5다. `Critical`이 하나라도 있으면 합산을 기다리지 않고 `Critical`이 되고, 그 외에는 총점에 따라 `Low`(1~14) / `Medium`(15~39) / `High`(40~99)로 나뉜다. `Low` 3건이 `Medium`으로 올라가듯, 저위험 신호가 겹칠수록 등급이 올라간다.

**이것이 약한 신호의 유일한 승격 경로다** —— 단일 약한 신호는 5점이라 40점 거부선을 영원히 넘지 못한다. 넘는 것은 여러 건(서로 다른 탐지기에서)이 겹칠 때뿐이다. 따라서 여러 차원의 입력을 같은 `Scanner`에 함께 넣는 편이 단일 필드만 스캔하는 것보다 약한 신호 뒤의 공격을 더 잘 보여 준다. 반대로 짧은 필드 하나만 스캔한다면 약한 신호에 대한 대응은 전혀 필요 없다.

## 모듈 경로

| 모듈 | 경로 | 탐지기 수 |
|------|------|---------|
| 핵심 | `src/lib.rs` `result.rs` `scanner.rs` | — |
| 인젝션 | `src/injection/` | 11 |
| 프로토콜 | `src/protocol/` | 11 |
| 데이터 | `src/data/` | 7 |
| 파일 | `src/file/` | 3 |
| 세션 | `src/session/` | — |
| 속도 제한 | `src/throttle/` | — |
| 스코어링 | `src/score.rs` | — |
| 펫 | `src/pet.rs` | — |

## 알려진 한계

다음은 **알려져 있고 의도적으로 남긴** 경계이며, 고쳐야 할 결함이 아니다. 바꾸기 전에 근거를 읽어 보라 —— 모두 실측에서 나왔고, 누군가 더 조이려다 같은 벽에 부딪힌 것들이다.

### `dns_rebinding`은 보고만 하고 막지 않는다

판정 기준은 "`Host:` 헤더에 사설 주소가 나타난다"인데, 같은 형태가 k8s의 모든 pod 간 호출(`Host: 10.244.1.5:8080`), 모든 로컬 개발(`Host: localhost:8000`), 모든 Docker 컨테이너 네트워크 요청(`172.18.0.2`)이기도 하다. 진짜 rebinding이 보는 것은 "공인 도메인 이름 + 해석 결과가 내부를 향함"이고, 브라우저가 보내는 `Host`는 바로 그 공인 도메인 이름이다 —— **단일 문자열에서는 해석 이력이 보이지 않는다**. 그래서 이 탐지기가 재는 형태는 공격 형태와 겹치지 않으며 조일 방향이 없다. 따라서 탐지기 전체가 약한 단계뿐이고 일괄 `Low`를 보고하며, 아무리 많이 겹쳐도 단독으로는 거부선을 넘지 않는다. 방어는 해석 **이후**에 결과 IP를 대조하는 곳에 있고 문자열 계층에는 없다.

### 이 라이브러리는 자기 소스·테스트·문서를 스캔할 수 없다

시그니처 스캐너의 천장: 실측으로 이 저장소의 298개 파일 중 78개가 거부선을 넘는데, 그 모두가 **구조상** 공격 문자열을 담고 있다 —— 테스트 페이로드, 탐지기 소스 자체의 정규식 리터럴, 그리고 이 패턴들을 나열하는 README와 OWASP 표다. README는 `(a+)+`를 적었다고 해서 결함이 되지 않는다. 자기 산출물을 스캔하려면 먼저 이 코퍼스를 제외하거나 다른 판정 기준으로 바꿔야 한다.

### `upload`는 `<%@` / `<?php`를 일괄 Critical로 보고한다

이 탐지기의 계약은 "**이 blob은 서버 측에서 실행 가능한 코드다**" —— 출현 자체로 성립하므로 강약 계층을 두지 않는다. JSP 페이지와 JSP 웹셸의 선두 바이트는 바이트 단위로 같고(`<%@ page language="java" … %>`와 `<%@ page import="java.io.*" %>`는 같은 형태다), `<%@`/`<%=`를 강등하는 것은 웹셸을 거부선 아래로 떨어뜨리는 일 —— 다른 방식으로 탐지를 지우는 것과 같다. 대가는 **현재 서비스 중인** 페이지(업로드된 파일이 아니라)를 스캔해도 적중한다는 것인데, 그것은 입력 영역의 불일치다.

### `path_traversal`은 `(?:\.\./){2,}`를 Critical로 보고한다

monorepo의 깊은 상대 경로(`from '../../../shared/domain'`)가 적중한다. 더 조이지 않은 이유는, 공격과 구분할 수 있는 유일한 제약이 대상 파일 이름 목록(`../etc/passwd` 류)인데 그것이 시스템 파일만 덮기 때문이다 —— 공격자는 LFI 대상을 바꾸면 빠져나간다.

## 성능

전체 32개 탐지기 스캔은 수십 µs/회다. 값은 CPU, 탐지기 수, 입력 길이에 의존하므로 자신의 하드웨어와 부하에서 직접 측정하라. 높은 처리량 시나리오(API 게이트웨이, 로그 파이프라인)에서는 `scan_with()`로 대상 탐지기를 좁히는 것을 검토하라.

각 탐지기의 정규식은 `LazyLock`의 `Vec<Regex>`로 보관되어 프로세스당 한 번만 컴파일된다(두 번째 스캔부터는 컴파일 비용이 들지 않는다).
