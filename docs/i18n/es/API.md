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
security-rust = "1.0.4"
```

### Inicio rápido

```rust
use security_rust::Scanner;

fn main() {
    // Cero configuración: ensambla los 27 detectores
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

## Rutas de los módulos

| Módulo | Ruta | N.º de detectores |
|------|------|---------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Inyección | `src/injection/` | 10 |
| Protocolo | `src/protocol/` | 9 |
| Datos | `src/data/` | 5 |
| Archivos | `src/file/` | 3 |

## Rendimiento

En builds Release, un detector individual escanea en ~100ns/operación (con RegexSet precompilado), y el escaneo completo con los 27 detectores tarda ~5μs/operación. Adecuado para escenarios de alto rendimiento (puertas de enlace de API, pipelines de logs).
