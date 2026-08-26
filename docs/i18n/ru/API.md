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
security-rust = "1.0.4"
```

### Быстрый старт

```rust
use security_rust::Scanner;

fn main() {
    // Ноль настроек: собирает все 27 детекторов
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

## Пути модулей

| Модуль | Путь | Кол-во детекторов |
|--------|------|-------------------|
| Ядро | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Инъекции | `src/injection/` | 10 |
| Протокол | `src/protocol/` | 9 |
| Данные | `src/data/` | 5 |
| Файлы | `src/file/` | 3 |

## Производительность

В release-сборке сканирование одним детектором занимает ~100 нс/раз (прекомпиляция RegexSet), полное сканирование всеми 27 детекторами — ~5 мкс/раз. Подходит для сценариев с высокой пропускной способностью (API-шлюзы, конвейеры логов).
