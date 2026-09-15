<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Справочник API security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Русский (本页)](./API.md)

---

## Базовый Trait

### `Detector`

Единственный контракт для всех детекторов:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — имя детектора (например, `"xss"`, `"sql_injection"`)
- `detect()` — сканирует входные данные; при совпадении возвращает `Some(DetectionResult)`, при отсутствии совпадения — `None`

## Структура результата обнаружения

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // совпавший фрагмент паттерна
    pub offset: usize,            // байтовое смещение во входных данных
    pub message: String,          // человекочитаемое описание
}
```

## Scanner

### Установка

```toml
[dependencies]
security-rust = "1.0.8"
```

### Быстрый старт

```rust
use security_rust::Scanner;

fn main() {
    // Ноль настроек: собирает все 32 детекторов
    let scanner = Scanner::default();

    // Сканирует входные данные и возвращает все обнаруженные атаки
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Вывод:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Выборочное сканирование

```rust
let scanner = Scanner::default();

// Запустить только указанные детекторы
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Пользовательская настройка

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Через builder собрать только нужные детекторы
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Отображение серьёзности

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## Модули с состоянием

`session` и `throttle` **намеренно не** реализуют трейт `Detector`: они хранят состояние и привязаны к идентичности, а `Detector::detect(&self, input: &str)` не способен выразить составной вход из токена, отпечатка, местоположения и времени. `score` — чистый расчёт над `DetectionResult`.

```rust
use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision,
};

// Защита сессии — fail-closed: Decision::Block при отказе хранилища
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // отклонить
}

// Ограничение частоты — эшелонированная защита: при сбое Unavailable, а не Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* отклонить: лимит исчерпан */ }
    ThrottleDecision::Allow { .. } => { /* пропустить */ }
    ThrottleDecision::Banned { until } => { /* бан до `until` */ }
    ThrottleDecision::Unavailable => { /* решать самостоятельно */ }
}

// Оценка риска: агрегировать отдельные сигналы в измеримую величину
let risk = Scanner::default().assess(input);
```

| Элемент | Сигнатура / поле |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | обновляет токен сессии |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Severity`, `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | трейт хранилища сессий; `MemoryStore` — встроенная реализация в памяти |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleDecision, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` |
| `ThrottleStore` | трейт хранилища счётчиков; `MemoryThrottleStore` — встроенная реализация в памяти |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | результат `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

Обратите внимание: `ThrottleDecision::Allow { remaining: 0 }` означает, что **этот** запрос нужно отклонить — лимит исчерпан, а не «осталась ещё одна попытка». Ветка называется `Allow`, а не `Banned`, потому что в этот момент бан не действует.

`RequestContext` целиком заполняет вызывающая сторона: библиотека не содержит геобазы и не проверяет подписи — она лишь сравнивает переданные значения с базой, сохранённой при `bind`.

## Пути модулей

| Модуль | Путь | Кол-во детекторов |
|--------|------|-------------------|
| Ядро | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Инъекции | `src/injection/` | 11 |
| Протокол | `src/protocol/` | 11 |
| Данные | `src/data/` | 7 |
| Файлы | `src/file/` | 3 |

## Производительность

Каждый детектор хранит свои шаблоны в статической таблице `static PATTERNS: LazyLock<Vec<Regex>>`: каждая регулярка компилируется один раз, при первом использовании в процессе, а затем переиспользуется при каждом вызове — без дополнительных затрат на компиляцию. Полное сканирование всеми 32 детекторами занимает десятки микросекунд на раз, и эта стоимость растёт с числом детекторов и длиной входа. Измеряйте реальное значение на своём оборудовании и под своей нагрузкой. Подходит для сценариев с высокой пропускной способностью (API-шлюзы, конвейеры логов).
