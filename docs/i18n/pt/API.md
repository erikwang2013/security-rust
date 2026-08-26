<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Referência da API security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Français](../fr/API.md) | [Español](../es/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Português (本页)](./API.md)

---

## Trait Principal

### `Detector`

O único contrato de todos os detectores:

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nome do detector (ex.: `"xss"`, `"sql_injection"`)
- `detect()` — escaneia a entrada; retorna `Some(DetectionResult)` em caso de correspondência, `None` caso contrário

## Estrutura do Resultado de Detecção

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // segmento específico do padrão correspondido
    pub offset: usize,            // deslocamento em bytes na entrada
    pub message: String,          // descrição legível por humanos
}
```

## Scanner

### Instalação

```toml
[dependencies]
security-rust = "1.0.4"
```

### Início Rápido

```rust
use security_rust::Scanner;

fn main() {
    // Zero configuração: monta todos os 27 detectores
    let scanner = Scanner::default();

    // Escaneia a entrada, retorna todos os ataques detectados
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Saída:
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Varredura Seletiva

```rust
let scanner = Scanner::default();

// Executa apenas os detectores especificados
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Configuração Personalizada

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// Monta apenas os detectores necessários via builder
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Exibição de Severidade

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

## Caminhos de Módulos

| Módulo | Caminho | Nº de detectores |
|------|------|---------|
| Núcleo | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injeção | `src/injection/` | 10 |
| Protocolo | `src/protocol/` | 9 |
| Dados | `src/data/` | 5 |
| Arquivos | `src/file/` | 3 |

## Desempenho

Em builds de release, a varredura com um único detector leva ~100ns/varredura (RegexSet pré-compilado), e a varredura completa com os 27 detectores leva aproximadamente ~5μs/varredura. Adequado para cenários de alto throughput (gateways de API, pipelines de log).
