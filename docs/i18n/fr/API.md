<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# Référence API security-rust

[中文](../../../README.md) | [English](../en/API.md) | [한국어](../ko/API.md) | [Русский](../ru/API.md) | [Deutsch](../de/API.md) | [Español](../es/API.md) | [Português](../pt/API.md) | [हिन्दी](../hi/API.md) | [العربية](../ar/API.md) | [বাংলা](../bn/API.md) | [Bahasa Indonesia](../id/API.md) | [日本語](../ja/API.md) | [Français (本页)](./API.md)

---

## Trait principal

### `Detector`

Le seul contrat de tous les détecteurs :

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
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

## Deux niveaux : signaux forts et signaux faibles

18 des 32 détecteurs répartissent leurs motifs en deux niveaux (les statiques `STRONG_PATTERNS` / `WEAK_PATTERNS` du code source). La structure de `DetectionResult` ne change pas ; c'est la valeur de `severity` qui change :

| Niveau | Critère | `severity` | Une correspondance isolée franchit-elle le seuil de rejet ? |
|------|------|-----------|------------------|
| **Fort** | La forme elle-même ne peut venir que d'une attaque | Le niveau déclaré du détecteur | Oui |
| **Faible** | Le jeton *apparaît* simplement — il pullule dans le contenu normal | Toujours `Severity::Low` (5 points) | **Non** |

Même détecteur, même `attack_type`, seule `severity` diffère ; `detect()` essaie d'abord le niveau fort et retombe sur le faible, donc **chaque détecteur renvoie au plus un résultat**. Les signaux faibles sont toujours détectés et ne disparaissent pas en silence.

`DetectionResult` ne distingue pas les niveaux — pour savoir si une correspondance est forte ou faible, il suffit de tester `severity == Severity::Low` (le niveau faible est la seule source qui signale `Low`). Le pipeline de référence rejette à 40 points (`risk.level >= RiskLevel::High`, voir [`examples/waf.rs:166`](../../../examples/waf.rs)) ; un signal faible isolé en vaut 5 et n'atteint pas cette branche.

Pour voir l'attaque derrière les signaux faibles, c'est `assess()` qui empile les correspondances de plusieurs détecteurs :

```rust
let scanner = Scanner::default();

// Trois signaux faibles de trois détecteurs différents — seul l'empilement atteint Medium (15 points), encore sous High
let a = scanner.assess("<script src=\"/app.js\"></script>\n../config\n__proto__");
assert_eq!(a.results, 3);
assert_eq!(a.score, 15);
assert_eq!(a.level, RiskLevel::Medium);
```

Exemples de formes rétrogradées (la liste complète figure dans les `WEAK_PATTERNS` de chaque détecteur) : `<script src=...>`, un `../` à un seul niveau, `-2` en début de ligne, un `__proto__` nu, `${env:}`, `X-Forwarded-Host`, `Host: localhost`, un `10.0.0.5` nu, `//evil.com`, `information_schema`.

Le critère est la **forme**, pas le nom du fichier : pour un même `../`, un seul niveau (`../x`) signale `Low` et plusieurs niveaux (`../../`) signalent `Critical` ([`src/file/path_traversal.rs`](../../../src/file/path_traversal.rs)). Le plafond de chaque détecteur figure dans les tableaux ci-dessous et dans les tableaux de fonctionnalités du [README](./README.md).

## Scanner

### Installation

```toml
[dependencies]
security-rust = "3.0.0"
```

### Démarrage rapide

```rust
use security_rust::Scanner;

fn main() {
    // Zéro configuration : assemble les 32 détecteurs
    let scanner = Scanner::default();

    // Analyse l'entrée et renvoie toutes les attaques détectées (au plus un résultat par détecteur)
    let results = scanner.scan("<img src=x onerror=alert(1)>");

    for r in &results {
        println!("[{}] {} — offset: {}, pattern: {}",
            r.severity, r.message, r.offset, r.matched_pattern);
    }
    // Sortie :
    // [CRITICAL] XSS cross-site scripting detected — offset: 11, pattern: onerror=

    // Un signal faible passe par le même détecteur et le même attack_type, mais signale Low
    let weak = scanner.scan("<script src=\"/app.js\"></script>");
    // [LOW] XSS tag present (weak signal) — offset: 0, pattern: <script>
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
    Decision, MemoryStore, MemoryThrottleStore, RequestContext, Scanner,
    SessionConfig, SessionGuard, SessionVerdict,
    Throttle, ThrottleConfig, ThrottleDecision, ThrottleOutcome,
};

let now = 1_700_000_000u64;
let ctx = RequestContext {
    token: "tok-1", subject: "user-42", fingerprint: "ip=203.0.113.7|ua=curl",
    location: Some("CN-BJ"), coords: Some((39.9042, 116.4074)), signature: Some("mac-abc"), at: Some(now),
};

// Protection de session — fail-closed : Decision::Block en cas de panne du stockage
let sessions = SessionGuard::new(MemoryStore::new(), SessionConfig::default());
let verdict: SessionVerdict = sessions.verify(&ctx, now);
if verdict.decision == Decision::Block {
    // refuser
}

// Limitation de débit — défense en profondeur : Unavailable en panne, pas Banned
let throttle = Throttle::new(MemoryThrottleStore::new(), ThrottleConfig::default());
match throttle.check("acct:user-42", now) {
    ThrottleDecision::Allow { remaining: 0 } => { /* refuser : quota épuisé */ }
    ThrottleDecision::Allow { .. } => { /* laisser passer */ }
    ThrottleDecision::Banned { until } => { /* banni jusqu'à `until` */ }
    ThrottleDecision::Unavailable => { /* décider soi-même */ }
}

// Fusionner plusieurs dimensions (par ex. IP + compte) : le résultat le plus strict l'emporte
let merged = throttle.check_any(&["ip:203.0.113.7", "acct:user-42"], now);
match throttle.record_failure("acct:user-42", now) {
    Ok(outcome) => { /* ThrottleOutcome: Allow { remaining } | Banned { until } */ }
    Err(_) => { /* erreur de stockage */ }
}

// Évaluation du risque : agréger les signaux isolés en une grandeur mesurable
let risk = Scanner::default().assess("<script>alert('xss')</script>");
```

| Élément | Signature / champ |
|------|------|
| `SessionGuard::bind` | `fn bind(&self, ctx: &RequestContext, now: u64) -> Result<SessionVerdict, SessionError>` |
| `SessionGuard::verify` | `fn verify(&self, ctx: &RequestContext, now: u64) -> SessionVerdict` |
| `SessionGuard::revoke` / `revoke_all` | `fn revoke(&self, token: &str) -> Result<(), StoreError>` / `fn revoke_all(&self, subject: &str) -> Result<usize, StoreError>` |
| `SessionGuard::rotate` | renouvelle le jeton d'une session |
| `SessionGuard::purge_expired` | supprime les sessions expirées et l'historique de connexion des sujets dormants. **La valeur de retour ne compte que les sessions**, pas l'historique de connexion récupéré |
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

**Le nombre de sujets n'est pas borné avec le backend en mémoire.** `MemoryStore` plafonne l'historique de connexion de chaque sujet à `MAX_LOGINS_PER_SUBJECT` = 10, mais **rien ne borne le nombre de sujets** (`Mutex<HashMap>`, aucun thread d'arrière-plan, des entrées qui ne font que croître). Un processus de longue durée devrait appeler `purge_expired` à intervalle régulier, de l'ordre de `ttl_secs` : il supprime les sessions dont `expires_at <= now`, ainsi que tout l'historique de connexion des sujets dont le dernier point de connexion est antérieur à `now - LOGIN_HISTORY_KEEP_SECS` (7 jours). **La valeur de retour ne compte que les sessions**, jamais l'historique récupéré. Récupérer l'historique d'un sujet dormant coûte à celui-ci une vérification de localisation distante / de voyage impossible en moins lors de sa prochaine connexion — c'est un faux négatif, pas un faux positif ; l'historique est reconstruit immédiatement après.

## Chemins des modules

| Module | Chemin | Nombre de détecteurs |
|------|------|---------|
| Noyau | `src/lib.rs` `result.rs` `scanner.rs` | — |
| Injection | `src/injection/` | 11 |
| Protocole | `src/protocol/` | 11 |
| Données | `src/data/` | 7 |
| Fichiers | `src/file/` | 3 |
| Mascotte | `src/pet.rs` | — |

## Limites connues

Les points suivants sont des limites **connues et volontairement conservées**, et non des défauts en attente de correction. Avant de les modifier, lisez la justification — chacune repose sur des mesures, et chacune a déjà repoussé une tentative de durcissement.

### `dns_rebinding` signale, il ne bloque pas

Son critère est « une adresse interne apparaît dans `Host:` » — et cette même forme est celle de tout appel pod à pod en k8s (`Host: 10.244.1.5:8080`), de tout développement local (`Host: localhost:8000`) et de toute requête sur le réseau de conteneurs Docker (`172.18.0.2`). Un vrai rebinding, c'est « un nom de domaine public + un résultat de résolution qui pointe vers l'intérieur », et le `Host` que le navigateur envoie est précisément ce nom public — **une chaîne isolée ne porte aucun historique de résolution** : la forme que ce détecteur teste ne recouvre pas la forme de l'attaque, et il n'existe aucune direction dans laquelle le durcir. Le détecteur est donc entièrement faible et signale toujours `Low` ; quel que soit le nombre de correspondances empilées, il ne franchit jamais le seuil de rejet à lui seul. La protection se situe après la résolution, dans la comparaison de l'IP obtenue — pas au niveau de la chaîne.

### Cette bibliothèque ne peut pas analyser son propre code source, ses tests ni sa documentation

Le plafond d'un scanner à signatures : mesuré sur ce dépôt, 78 fichiers sur 298 franchissent le seuil de rejet, et ils contiennent tous des chaînes d'attaque **par construction** — charges de test, littéraux d'expression régulière du code des détecteurs eux-mêmes, et tableaux README/OWASP qui nomment ces motifs. Un README n'est pas défectueux parce qu'il liste `(a+)+`. Analyser ses propres artefacts suppose d'exclure d'abord ce corpus — ou de choisir un autre critère.

### `upload` signale `<%@` / `<?php` comme Critical où qu'ils apparaissent

Le contrat de ce détecteur est « **ce blob est du code exécutable côté serveur** » — la présence suffit, il n'y a donc pas de répartition en niveaux. Une page JSP et un webshell JSP partagent leur préambule octet pour octet (`<%@ page language="java" … %>` et `<%@ page import="java.io.*" %>` ont la même forme) ; rétrograder `<%@`/`<%=` ferait passer les webshells sous le seuil de rejet — une suppression sous un autre nom. Le prix à payer : analyser une page **en cours de service** (et non un fichier téléversé) déclenche aussi une détection ; c'est un domaine d'entrée inadéquat.

### `path_traversal` signale `(?:\.\./){2,}` comme Critical

Un chemin relatif profond dans un monorepo (`from '../../../shared/domain'`) est détecté. Le durcissement s'arrête là, car la seule contrainte qui le sépare d'une attaque est une liste de noms de fichiers cibles (`../etc/passwd` et compagnie) — et elle ne couvre que les fichiers système : l'attaquant choisit simplement une autre cible de LFI.

## Performances

Chaque détecteur conserve ses motifs dans une table statique `static PATTERNS: LazyLock<Vec<Regex>>` : chaque expression est compilée une seule fois, à sa première utilisation dans le processus, puis réutilisée à chaque appel, sans coût de compilation supplémentaire. La totalité des 32 détecteurs analyse une entrée en quelques dizaines de microsecondes ; ce coût augmente avec le nombre de détecteurs et la longueur de l'entrée. Mesurez la valeur réelle sur votre propre matériel et sous votre propre charge. Convient aux scénarios à haut débit (passerelles API, pipelines de journaux).
