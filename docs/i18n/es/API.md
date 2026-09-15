<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referencia de la API de security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Español (本页)](./API.md)

---

## Trait principal

### `Detector`

El único contrato de todos los detectores:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nombre del detector (p. ej. `"xss"`, `"sql_injection"`)
- `detect()` — escanea la entrada; si hay coincidencia devuelve `Some(DetectionResult)`, si no hay coincidencia devuelve `None`

## Estructura del resultado de detección

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // fragmento del patrón concreto que coincidió
    pub offset: usize,            // desplazamiento de bytes en la entrada
    pub message: String,          // descripción legible por humanos
}
```

## Scanner

### Instalación

```toml
[dependencies]
security-rust = "1.1.0"
```

### Inicio rápido

```rust
use security_rust::Scanner;

fn main() {
    // Cero configuración: ensambla los 32 detectores
    let scanner = Scanner::default();

    // Escanea la entrada y devuelve todos los ataques detectados
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Salida:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Escaneo selectivo

```rust
let scanner = Scanner::default();

// Ejecuta solo los detectores especificados
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Configuración personalizada

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Ensambla solo los detectores necesarios mediante el builder
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Visualización de la severidad

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

Las demás etiquetas de estado también implementan `Display` y se imprimen en mayúsculas: `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (p. ej. `impossible travel (11205 km/h)`), `AttackCategory` (en minúsculas, p. ej. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`) y `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Módulos con estado

`session` y `throttle` **no** implementan el trait `Detector` de forma deliberada: tienen estado y están ligados a una identidad, y `Detector::detect(&self, input: &str)` no puede expresar una entrada compuesta de token, huella, posición y tiempo. `score` es un cálculo puro sobre `DetectionResult`.

```rust
use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

// Protección de sesión — fail-closed: Decision::Block si falla el almacenamiento
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // rechazar
}

// Limitación de tasa — defensa en profundidad: Unavailable si falla, no Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* rechazar: cupo agotado */ }
    ThrottleDecision::Allow { .. } => { /* dejar pasar */ }
    ThrottleDecision::Banned { until } => { /* bloqueado hasta `until` */ }
    ThrottleDecision::Unavailable => { /* decidir por cuenta propia */ }


// Fusionar varias dimensiones (p. ej. IP + cuenta): gana el resultado más estricto
let merged = throttle.check_any(&["ip:203.0.113.7", "user:42"], now);
match throttle.record_failure("user:42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* fallo del almacén */ }
}
}

// Evaluación de riesgo: agregar señales sueltas en una magnitud medible
let risk = Scanner::default().assess(input);
```

| Elemento | Firma / campo |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | renueva el token de una sesión |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (`None` si se permite), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | trait del almacenamiento de sesiones; `MemoryStore` es la implementación en memoria incluida |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::check_any` | `fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision` — fusiona varias dimensiones: `Banned` gana (con el `until` más tardío), si no `Unavailable`, si no `Allow` con el `remaining` mínimo |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` — solo lo producen `check` / `check_any` |
| `ThrottleOutcome` | `Allow { remaining }` \| `Banned { until }` — resultado de `record_failure`; sin `Unavailable`, porque allí un fallo del almacén llega como `Err(StoreError)` |
| `ThrottleStore` | trait del almacenamiento de contadores; `MemoryThrottleStore` es la implementación en memoria incluida |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | resultado de `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

Nota: `ThrottleDecision::Allow { remaining: 0 }` significa que **esta** petición debe rechazarse — el cupo está agotado, no es «queda un intento». La variante se llama `Allow` y no `Banned` porque en ese instante no hay ningún bloqueo activo. `Unavailable` solo lo producen `check` / `check_any`; `record_failure` devuelve `ThrottleOutcome`, que deliberadamente carece de esa variante: un fallo del almacén se convierte allí en `Err(StoreError)`.

El llamador rellena por completo un `RequestContext`: la biblioteca no incorpora una base geográfica ni valida firmas; solo compara los valores recibidos con la base registrada en `bind`.

`subject` **solo lo usa `bind`; `verify` lo ignora por completo** — la identidad que se comprueba en cada petición procede siempre del `SessionRecord` del servidor (el historial de ubicaciones remotas se agrega sobre `record.subject`), y el valor que envía el solicitante no es de fiar. Por eso `subject: ""` desde un middleware es válido (`bind` sí exige un valor no vacío). Y por eso mismo **nunca** debe ponerse aquí un identificador de usuario tomado de una cabecera de la petición: hoy no llega a la decisión, pero una refactorización futura no está obligada a mantenerlo así.

## Rutas de los módulos

| Módulo | Ruta | N.º de detectores |
|------|------|---------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Inyección | `src/injection/` | 11 |
| Protocolo | `src/protocol/` | 11 |
| Datos | `src/data/` | 7 |
| Archivos | `src/file/` | 3 |

## Rendimiento

Cada detector guarda sus patrones en una tabla estática `static PATTERNS: LazyLock<Vec<Regex>>`: cada expresión regular se compila una sola vez, en su primer uso dentro del proceso, y se reutiliza en cada llamada posterior, sin coste de compilación añadido. El escaneo completo con los 32 detectores tarda decenas de microsegundos por operación, y ese coste crece con el número de detectores y la longitud de la entrada. Mide el valor real en tu propio hardware y con tu carga de trabajo. Adecuado para escenarios de alto rendimiento (puertas de enlace de API, pipelines de logs).
