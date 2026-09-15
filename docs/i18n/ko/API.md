<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust API 참조

[中文](../../README.md) | [English](../en/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [한국어 (本页)](./API.md)

---

## 핵심 Trait

### `Detector`

모든 탐지기의 유일한 계약:

```rust
pub trait Detector {
    fn name(&self) -> &str;
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

## Scanner

### 설치

```toml
[dependencies]
security-rust = "1.0.4"
```

### 빠른 시작

```rust
use security_rust::Scanner;

fn main() {
    // 설정 없이 전체 32개 탐지기 장착
    let scanner = Scanner::default();

    // 입력을 스캔하여 탐지된 모든 공격을 반환한다
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // 출력:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
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

- `SessionGuard<S: SessionStore>` — `bind` / `verify` / `revoke` / `revoke_all` / `rotate`
- `SessionVerdict` — `decision: Decision`(`Allow` / `Challenge` / `Block`), `severity`, `threats: Vec<SessionThreat>`
- `SessionConfig` — `ttl_secs`(기본 3600), `impossible_travel_kmh`(기본 900.0), `timestamp_skew_secs`(기본 300)
- `SessionStore` trait과 `MemoryStore`

**fail-closed** — 저장소 장애 시 `SessionThreat::StoreUnavailable`을 동반한 `Decision::Block`을 반환하며, 절대 통과시키지 않는다. 인증 게이트가 fail-open이면 저장소를 죽이는 것만으로 인증을 우회할 수 있기 때문이다.

`token`과 `signature`(MAC)는 호출자가 준비하고, `location` / `coords`도 호출자가 파싱해 넘긴다. 라이브러리 의존성을 `regex` 하나로 유지하기 위해 token 발급도, 서명 검증도, geo 데이터베이스도 갖지 않는다.

## 속도 제한과 차단 (`throttle`)

슬라이딩 윈도 내 실패 횟수 집계, 임계치 도달 시 차단, 계정 잠금을 담당한다.

```rust
use security_rust::throttle::{MemoryThrottleStore, Throttle, ThrottleConfig, ThrottleDecision};

let now = 1_700_000_000u64;
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());

match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining } => {
        // X-RateLimit-*에 실어 보낸다. remaining == 0이면 이 요청은 거부해야 한다
    }
    ThrottleDecision::Banned { until } => { /* now >= until이면 해제된 상태 */ }
    ThrottleDecision::Unavailable => { /* 백엔드 장애. 판단은 호출자에게 */ }
}

// 인증 실패·성공을 기록해 윈도를 진행시킨다
throttle.record_failure("user:42", now)?;
throttle.record_success("user:42")?;
```

- `Throttle<S: ThrottleStore>` — `check` / `record_failure` / `record_success` / `reset` / `purge_expired`
- `ThrottleConfig` — `threshold`(기본 5), `window_secs`(기본 60), `ban_secs`(기본 900)
- `ThrottleStore` trait과 `MemoryThrottleStore`

`Allow { remaining: 0 }`은 "한 번 더 시도 가능"이 아니라 "이 요청은 거부해야 함"을 뜻한다.

**가용성 측의 예외** — 저장소 장애 시 `ThrottleDecision::Unavailable`을 반환하며 `Banned`로는 만들지 않는다. 전체 사용자를 막아서는 것은 자기 DoS이고, 속도 제한은 주된 인증 게이트가 아니라 다층 방어이기 때문이다. `SessionGuard`의 fail-closed와 의도적으로 다르며, 이 분기는 `check`에 고정되어 있다(`Err`가 `Banned`로 사상되는 일은 없다).

**저장소** — 두 모듈 모두 `SessionStore` / `ThrottleStore` trait으로 백엔드를 추상화한다. 다중 인스턴스 배포에서는 이 trait을 구현해 Redis 등을 끼워 넣으면 된다.

## 위험 스코어링 (`score`)

개별 탐지 결과는 "그 공격이 있었다"는 사실만 말해 준다. `score`는 이를 가중 합산해 관측 가능한 위험 값으로 바꾼다.

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let assessment = scanner.assess("<script>alert(1)</script>");

println!("{} / {} / {}", assessment.level, assessment.score, assessment.results);
// CRITICAL | HIGH | MEDIUM | LOW | NONE
```

- `RiskLevel` — `None` / `Low` / `Medium` / `High` / `Critical`
- `RiskAssessment` — `level`, `score`(가중치 합), `results`(합산에 참여한 건수)
- `Scanner::assess(&str) -> RiskAssessment`, 그리고 자유 함수 `score::assess(&[DetectionResult])`

가중치는 `Critical`=100, `High`=40, `Medium`=15, `Low`=5다. `Critical`이 하나라도 있으면 합산을 기다리지 않고 `Critical`이 되고, 그 외에는 총점에 따라 `Low`(1~14) / `Medium`(15~39) / `High`(40~99)로 나뉜다. `Low` 3건이 `Medium`으로 올라가듯, 저위험 신호가 겹칠수록 등급이 올라간다.

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

## 성능

Release 빌드 실측(노트북, 단일 스레드)에서 단일 탐지기 스캔은 1µs 전후, 전체 32개 탐지기 스캔은 수십 µs/회다. 값은 CPU와 입력 길이에 의존한다. 높은 처리량 시나리오(API 게이트웨이, 로그 파이프라인)에서는 `scan_with()`로 대상 탐지기를 좁히는 것을 검토하라.

각 탐지기의 정규식은 `LazyLock`의 `Vec<Regex>`로 보관되어 프로세스당 한 번만 컴파일된다(두 번째 스캔부터는 컴파일 비용이 들지 않는다).
