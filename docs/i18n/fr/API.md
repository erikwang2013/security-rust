<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Référence API security-rust

[中文](../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Français (本页)](./API.md)

---

## Trait principal

### `Detector`

Le seul contrat de tous les détecteurs :

```rust
pub trait Detector {
    fn name(&self) -> &str;
    fn detect(&self, input: &str) -> Option<DetectionResult>;
}
```

- `name()` — nom du détecteur (ex. `"xss"`, `"sql_injection"`)
- `detect()` — analyse l'entrée ; renvoie `Some(DetectionResult)` en cas de correspondance, `None` sinon

## Structure du résultat de détection

```rust
pub struct DetectionResult {
    pub attack_type: String,      // "xss", "sql_injection" ...
    pub category: AttackCategory, // Injection | Protocol | Data | File
    pub severity: Severity,       // Critical | High | Medium | Low
    pub matched_pattern: String,  // le fragment de motif effectivement trouvé
    pub offset: usize,            // décalage en octets dans l'entrée
    pub message: String,          // description lisible par un humain
}
```

## Scanner

### Installation

```toml
[dependencies]
security-rust = "2.0.0"
```

### Démarrage rapide

```rust
use security_rust::Scanner;

fn main() {
    // Zéro configuration : assemble les 32 détecteurs
    let scanner = Scanner::default();

    // Analyse l'entrée et renvoie toutes les attaques détectées
    let results = scanner.scan("<script>alert('xss')</script>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Sortie :
    // [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
}
```

### Scan sélectif

```rust
let scanner = Scanner::default();

// Exécute uniquement les détecteurs indiqués
let results = scanner.scan_with(
    "1 UNION SELECT password FROM users",
    &["sql_injection", "xss"],
);
```

### Configuration personnalisée

```rust
use security_rust::injection::{XssDetector, SqlInjectionDetector};

// N'assemble que les détecteurs nécessaires via le builder
let scanner = Scanner::builder()
    .with_detector(Box::new(XssDetector))
    .with_detector(Box::new(SqlInjectionDetector))
    .build();
```

### Affichage de la sévérité

```rust
use security_rust::Severity;

let r = &results[0];
println!("{}", r.severity);  // CRITICAL | HIGH | MEDIUM | LOW
```

Les autres étiquettes d'état implémentent elles aussi `Display` et s'affichent en majuscules : `Decision` (`ALLOW` / `CHALLENGE` / `BLOCK`), `SessionThreat` (par ex. `impossible travel (11205 km/h)`), `AttackCategory` (en minuscules, par ex. `injection`), `ThrottleDecision` (`ALLOW` / `BANNED` / `UNAVAILABLE`) et `ThrottleOutcome` (`ALLOW` / `BANNED`).

```rust
println!("{} {}", verdict.decision, verdict.threats.len());  // BLOCK 2
```

## Modules à état

`session` et `throttle` n'implémentent **délibérément pas** le trait `Detector` : ils sont à état et liés à une identité, et `Detector::detect(&self, input: &str)` ne peut pas exprimer une entrée composite faite de jeton, d'empreinte, de position et de temps. `score` est un simple calcul sur `DetectionResult`.

```rust
use security_rust::{
    Decision, MemoryStore, MemoryThrottleStore, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

// Protection de session — fail-closed : Decision::Block en cas de panne du stockage
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // refuser
}

// Limitation de débit — défense en profondeur : Unavailable en panne, pas Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("user:42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* refuser : quota épuisé */ }
    ThrottleDecision::Allow { .. } => { /* laisser passer */ }
    ThrottleDecision::Banned { until } => { /* banni jusqu'à `until` */ }
    ThrottleDecision::Unavailable => { /* décider soi-même */ }


// Fusionner plusieurs dimensions (par ex. IP + compte) : le résultat le plus strict l'emporte
let merged = throttle.check_any(&["ip:203.0.113.7", "user:42"], now);
match throttle.record_failure("user:42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* erreur de stockage */ }
}
}

// Évaluation du risque : agréger les signaux isolés en une grandeur mesurable
let risk = Scanner::default().assess(input);
```

| Élément | Signature / champ |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | renouvelle le jeton d'une session |
| `RequestContext` | `token`, `subject`, `fingerprint`, `location`, `coords`, `signature`, `at` |
| `SessionVerdict` | `decision: Decision`, `severity: Option<Severity>` (`None` en cas de passage), `threats: Vec<SessionThreat>` |
| `Decision` | `Allow` \| `Challenge` \| `Block` |
| `SessionConfig` | `ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300 |
| `SessionStore` | trait du stockage de sessions ; `MemoryStore` est l'implémentation en mémoire fournie |
| `Throttle::check` | `fn check(&self, key: &str, now: u64) -> ThrottleDecision` |
| `Throttle::check_any` | `fn check_any(&self, keys: &[&str], now: u64) -> ThrottleDecision` — fusionne plusieurs dimensions : `Banned` l'emporte (avec le `until` le plus tard), sinon `Unavailable`, sinon `Allow` avec le `remaining` minimal |
| `Throttle::record_failure` | `fn record_failure(&self, key: &str, now: u64) -> Result<ThrottleOutcome, StoreError>` |
| `Throttle::record_success` / `reset` / `purge_expired` | `fn record_success(&self, key: &str) -> Result<(), StoreError>` / `fn reset(&self, key: &str) -> Result<(), StoreError>` / `fn purge_expired(&self, now: u64) -> Result<usize, StoreError>` |
| `ThrottleConfig` | `threshold` 5, `window_secs` 60, `ban_secs` 900 |
| `ThrottleDecision` | `Allow { remaining }` \| `Banned { until }` \| `Unavailable` — produit uniquement par `check` / `check_any` |
| `ThrottleOutcome` | `Allow { remaining }` \| `Banned { until }` — résultat de `record_failure` ; sans `Unavailable`, car une erreur de stockage y remonte en `Err(StoreError)` |
| `ThrottleStore` | trait du stockage des compteurs ; `MemoryThrottleStore` est l'implémentation en mémoire fournie |
| `RiskLevel` | `None` \| `Low` \| `Medium` \| `High` \| `Critical` |
| `RiskAssessment` | résultat de `Scanner::assess` |
| `Scanner::assess` | `fn assess(&self, input: &str) -> RiskAssessment` |

À noter : `ThrottleDecision::Allow { remaining: 0 }` signifie que **cette** requête doit être refusée — le quota est épuisé, et non « il reste un essai ». La variante s'appelle `Allow` et non `Banned` parce qu'aucun bannissement n'est actif à cet instant. `Unavailable` n'est produit que par `check` / `check_any` ; `record_failure` retourne `ThrottleOutcome`, qui en est délibérément dépourvu — une erreur de stockage y devient `Err(StoreError)`.

Un `RequestContext` est entièrement rempli par l'appelant : la bibliothèque ne fournit pas de base géographique et ne valide pas les signatures ; elle compare seulement les valeurs transmises à la base enregistrée lors du `bind`.

`subject` **n'est utilisé que par `bind` ; `verify` l'ignore totalement** — l'identité vérifiée à chaque requête provient toujours du `SessionRecord` côté serveur (l'historique des lieux distants s'agrège sur `record.subject`), et la valeur fournie par l'appelant n'est pas fiable. `subject: ""` depuis un middleware est donc valide (`bind`, lui, exige une valeur non vide). C'est précisément pourquoi il ne faut **jamais** y placer un identifiant utilisateur issu d'un en-tête de requête : aujourd'hui il n'atteint pas la décision, mais une refactorisation future n'est pas tenue de préserver cela.

## Chemins des modules

| Module | Chemin | Nombre de détecteurs |
|------|------|---------|
| Noyau | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injection | `src/injection/` | 11 |
| Protocole | `src/protocol/` | 11 |
| Données | `src/data/` | 7 |
| Fichiers | `src/file/` | 3 |

## Performances

Chaque détecteur conserve ses motifs dans une table statique `static PATTERNS: LazyLock<Vec<Regex>>` : chaque expression est compilée une seule fois, à sa première utilisation dans le processus, puis réutilisée à chaque appel, sans coût de compilation supplémentaire. La totalité des 32 détecteurs analyse une entrée en quelques dizaines de microsecondes ; ce coût augmente avec le nombre de détecteurs et la longueur de l'entrée. Mesurez la valeur réelle sur votre propre matériel et sous votre propre charge. Convient aux scénarios à haut débit (passerelles API, pipelines de journaux).
