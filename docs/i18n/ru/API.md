<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Справочник API security-rust

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Русский (本页)](./API.md)

---

## Базовый Trait

### `Detector`

Единственный контракт для всех детекторов:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## Два уровня сигналов: сильные и слабые

18 из 32 детекторов делят свои паттерны на два уровня (статические таблицы `STRONG_PATTERNS` / `WEAK_PATTERNS` в исходниках). Структура полей `DetectionResult` не изменилась — изменилось значение `severity`:

| Уровень | Критерий | `severity` | Одиночное совпадение пересекает порог отказа |
|------|------|-----------|------------------|
| **Сильный сигнал** | Сама форма может возникнуть только из атаки | Объявленный уровень детектора | Да |
| **Слабый сигнал** | Токен всего лишь «встречается» — в обычном содержимом он повсюду | Всегда `Severity::Low` (5 баллов) | **Нет** |

Один и тот же детектор, один и тот же `attack_type`, различается только `severity`; `detect()` сначала пробует сильный уровень и лишь затем слабый, поэтому **каждый детектор возвращает не более одного результата**. Слабые сигналы по-прежнему обнаруживаются и не теряются молча.

Сам `DetectionResult` уровень не различает — чтобы понять, сильное это совпадение или слабое, достаточно проверить `severity == Severity::Low` (слабый уровень — единственный источник, сообщающий `Low`). Порог отказа эталонного конвейера — 40 баллов (`risk.level >= RiskLevel::High`, см. [`examples/waf.rs:166`](../../../examples/waf.rs)); одиночный слабый сигнал стоит 5 баллов и в эту ветку не попадает.

Разглядеть атаку за слабыми сигналами позволяет `assess()`, складывающий совпадения нескольких детекторов; это **единственный путь повышения уровня для слабого сигнала** — 5 баллов никогда не перейдут порог в 40, это делает только сумма нескольких совпадений (от разных детекторов). Поэтому подавать в один `Scanner` входные данные всех измерений полезнее, чем сканировать одно поле: так атака за слабыми сигналами становится видна. И наоборот: если сканируется одно короткое поле, никаких действий по слабым сигналам предпринимать не нужно.

```rust
let scanner = Scanner::default();

// Три слабых сигнала попали в три разных детектора: до Medium (15 баллов) дотягивает только сумма, High — нет
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

Примеры форм, переведённых в слабый уровень (полный список — в `WEAK_PATTERNS` каждого детектора): `<script src=...>`, одноуровневый `../`, `-2` в начале строки, голый `__proto__`, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, голый `10.0.0.5`, `//evil.com`, `information_schema`.

Критерий — **форма**, а не имя файла: для того же `../` один уровень (`../x`) сообщается как `Low`, а несколько (`../../`) — как `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Насколько высоко может дотянуться каждый детектор — см. таблицы ниже и таблицы функций в [README](./README.md).

## Scanner

### Установка

```toml
[dependencies]
security-rust = "3.0.0"
```

### Быстрый старт

```rust
use security_rust::Scanner;

fn main() {
    // Ноль настроек: собирает все 32 детекторов
    let scanner = Scanner::default();

    // Сканирует входные данные и возвращает все обнаруженные атаки (не более одной на детектор)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Вывод:
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // Слабый сигнал идёт через тот же детектор и тот же attack_type, отличается только severity = Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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

Остальные метки состояний тоже реализуют `Display` и выводятся в верхнем регистре: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (например, `impossible travel (11205 km/h)`), `AttackCategory` (в нижнем регистре, например `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`) и `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Модули с состоянием

`session` и `throttle` **намеренно не** реализуют трейт `Detector`: они хранят состояние и привязаны к идентичности, а `Detector::detect(&self, input: &str)` не способен выразить составной вход из токена, отпечатка, местоположения и времени. `score` — чистый расчёт над `DetectionResult`.

```rust
use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, RequestContext, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

let now = 1_700_000_000u64;
let ctx = RequestContext {
    token: "tok-1", subject: "user-42", fingerprint: "ip=203.0.113.7|ua=curl",
    location: Some("CN-BJ"), coords: Some((39.9042, 116.4074)), signature: Some("mac-abc"), at: Some(now),
};

// Защита сессии — fail-closed: Decision::Block при отказе хранилища
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // отклонить
}

// Ограничение частоты — эшелонированная защита: при сбое Unavailable, а не Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* отклонить: лимит исчерпан */ }
    ThrottleDecision::Allow { .. } => { /* пропустить */ }
    ThrottleDecision::Banned { until } => { /* бан до `until` */ }
    ThrottleDecision::Unavailable => { /* решать самостоятельно */ }
}

// Объединить несколько измерений (например, IP + аккаунт): побеждает самый строгий результат
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* сбой хранилища */ }
}

// Оценка риска: агрегировать отдельные сигналы в измеримую величину
// (сильный сигнал: одиночный тег — это `Low` + 5 баллов, этого мало)
let risk = Scanner::default().assess("<img src=x onerror=alert(1)>");
```

| Элемент | Сигнатура / поле |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | обновляет токен сессии |
| `SessionGuard::purge_expired` | `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` — удаляет сессии с `expires_at <= now` и историю входов спящих subject'ов. **Возвращаемое значение считает только сессии**, без переработанной истории входов |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (`None` при пропуске), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | трейт хранилища сессий; `MemoryStore` — встроенная реализация в памяти |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::check_any` | `fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision` — объединяет несколько измерений: побеждает `Banned` (с самым поздним `until`), иначе `Unavailable`, иначе `Allow` с минимальным `remaining` |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` — только из `check` / `check_any` |
| `ThrottleOutcome` | `Allow { remaining }` \| `Banned { until }` — результат `record_failure`; без `Unavailable`, потому что сбой хранилища возвращается там как `Err(StoreError)` |
| `ThrottleStore` | трейт хранилища счётчиков; `MemoryThrottleStore` — встроенная реализация в памяти |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | результат `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

Обратите внимание: `ThrottleDecision::Allow { remaining: 0 }` означает, что **этот** запрос нужно отклонить — лимит исчерпан, а не «осталась ещё одна попытка». Ветка называется `Allow`, а не `Banned`, потому что в этот момент бан не действует. `Unavailable` возникает только в `check` / `check_any`; `record_failure` возвращает `ThrottleOutcome`, где этой ветки сознательно нет — сбой хранилища превращается там в `Err(StoreError)`.

`RequestContext` целиком заполняет вызывающая сторона: библиотека не содержит геобазы и не проверяет подписи — она лишь сравнивает переданные значения с базой, сохранённой при `bind`.

У `MemoryStore` **число subject'ов не ограничено**: длина истории входов каждого subject'а ограничена константой `MAX_LOGINS_PER_SUBJECT` = 10, а вот число самих subject'ов — нет (`Mutex<HashMap>`, без фонового потока, записи только добавляются). Долго живущий процесс должен по таймеру вызывать `purge_expired` с интервалом порядка `ttl_secs`: он удаляет сессии с `expires_at <= now`, а также всю историю входов тех subject'ов, у которых последняя точка входа старше `now - LOGIN_HISTORY_KEEP_SECS` (7 дней). **Возвращаемое значение считает только сессии**, без переработанной истории входов. Возврат истории спящего subject'а стоит того, что при следующем входе для него пропускается одна проверка на смену локации / невозможное перемещение — это пропуск атаки, а не ложное срабатывание, и история сразу же строится заново.

`subject` **используется только в `bind`, а `verify` полностью его игнорирует** — проверяемая на каждом запросе идентичность всегда берётся из серверного `SessionRecord` (история чужих локаций агрегируется по `record.subject`), а значение, переданное запрашивающей стороной, не является доверенным. Поэтому `subject: ""` из middleware допустим (`bind` — тот требует непустое значение). Именно поэтому сюда **ни в коем случае** нельзя подставлять идентификатор пользователя из заголовка запроса: сегодня он не доходит до решения, но будущий рефакторинг не обязан это сохранять.

## Пути модулей

| Модуль | Путь | Кол-во детекторов |
|--------|------|-------------------|
| Ядро | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Инъекции | `src/injection/` | 11 |
| Протокол | `src/protocol/` | 11 |
| Данные | `src/data/` | 7 |
| Файлы | `src/file/` | 3 |
| Питомец | `src/pet.rs` | — |

## Известные ограничения

Ниже — **известные и намеренно сохранённые** границы, а не ждущие исправления дефекты. Прежде чем что-то менять, прочтите обоснование: каждая граница получена измерением, и каждую уже пробовали затянуть — и упирались в ту же стену.

### `dns_rebinding` только сообщает, но не блокирует

Критерий — «в заголовке `Host:` появляется внутренний адрес», а та же форма — это и каждый вызов pod-to-pod в k8s (`Host: 10.244.1.5:8080`), и каждая локальная разработка (`Host: localhost:8000`), и каждый запрос в сети Docker-контейнера (`172.18.0.2`). Настоящий rebinding — это «публичное доменное имя + результат разрешения, указывающий внутрь», а `Host`, который отправляет браузер, — как раз это публичное имя: **в одной строке нет истории разрешения**, форма, которую проверяет детектор, не совпадает с формой атаки, и затягивать здесь нечего. Поэтому весь детектор слабый, всегда `Low`, и сколько бы совпадений ни сложилось, в одиночку он порог отказа не пересечёт. Защита — сравнение IP **после** разрешения, а не на строковом уровне.

### Эта библиотека не может сканировать собственные исходники, тесты и документацию

Потолок сигнатурного сканера: измерено, что в этом репозитории 78 файлов из 298 пересекают порог отказа, и все они содержат атакующие строки **по построению** — тестовые полезные нагрузки, собственные литералы регулярных выражений в исходниках детекторов, а также README и таблицы OWASP, где эти паттерны перечислены. README не становится дефектом оттого, что в нём написан `(a+)+`. Чтобы просканировать собственные артефакты, этот корпус придётся сначала исключить — или взять другой критерий.

### `upload` сообщает `<%@` / `<?php` как Critical всегда

Контракт этого детектора — «**этот blob есть серверный исполняемый код**»: появление уже достаточно, поэтому уровни здесь не вводятся. Преамбула JSP-страницы и JSP-webshell совпадает байт в байт (`<%@ page language="java" … %>` и `<%@ page import="java.io.*" %>` — одна и та же форма), а перевод `<%@`/`<%=` на слабый уровень опустил бы webshell ниже порога отказа — то есть удалил бы детектор под другим названием. Цена: сканирование страницы, **которая сейчас отдаётся клиентам** (а не загружаемого файла), тоже даёт совпадение — это несовпадение области входа.

### `path_traversal` сообщает `(?:\.\./){2,}` как Critical

Глубокие относительные пути в монорепозитории (`from '../../../shared/domain'`) дают совпадение. Дальше не затянуто, потому что единственное ограничение, отделяющее это от атаки, — список имён целевых файлов (`../etc/passwd` и подобные), а он покрывает только системные файлы: атакующий просто выберет другую цель для LFI.

## Производительность

Каждый детектор хранит свои шаблоны в статической таблице `static PATTERNS: LazyLock<Vec<Regex>>`: каждая регулярка компилируется один раз, при первом использовании в процессе, а затем переиспользуется при каждом вызове — без дополнительных затрат на компиляцию. Полное сканирование всеми 32 детекторами занимает десятки микросекунд на раз, и эта стоимость растёт с числом детекторов и длиной входа. Измеряйте реальное значение на своём оборудовании и под своей нагрузкой. Подходит для сценариев с высокой пропускной способностью (API-шлюзы, конвейеры логов).
