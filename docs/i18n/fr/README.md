<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# security-rust

**🌐 [中文 (原文)](../../README.md)**

Bibliothèque de détection d'attaques écrite en Rust, couvrant 4 grandes catégories — attaques par injection, attaques par protocole, attaques de données/sérialisation et fuites de fichiers/données sensibles — pour un total de 32 détecteurs. Aucune dépendance à un framework externe : la chaîne de détecteurs travaille uniquement sur des chaînes, complétée par trois modules à état (voir ci-dessous).

---

## Conception

### Pourquoi « détection » plutôt qu'« interception »

Cette bibliothèque se positionne comme un **analyseur d'entrées pur** — elle reçoit une chaîne de caractères et renvoie un résultat de détection structuré. Elle n'est liée à aucun framework Web, n'analyse pas les requêtes/réponses HTTP et ne met pas en œuvre de blocage en temps réel. Vous pouvez ainsi l'intégrer dans n'importe quelle chaîne : moteur de règles WAF, audit de journaux, validation en amont des passerelles API, outils CLI de scan de sécurité, etc. Les modules `session`, `throttle` et `score` (voir ci-dessous) vont au-delà : ils conservent un état ou agrègent des signaux, sans pour autant dépendre d'un framework.

### Principes d'architecture

- **Responsabilité unique** — chaque détecteur ne gère qu'un type d'attaque et contient en interne un ensemble de motifs de regex compilés
- **Interface unifiée** — le trait `Detector` est le seul contrat de tous les détecteurs : `fn detect(&self, input: &str) -> Option<DetectionResult>`
- **Couverture par défaut** — `Scanner::default()` assemble en une seule fois les 32 détecteurs, utilisable sans aucune configuration
- **Configuration optionnelle** — `Scanner::builder()` permet une personnalisation à la demande, en assemblant sélectivement les détecteurs via `.with_detector()`

### Compromis

| Décision | Choix | Raison |
|------|------|------|
| Regex vs analyseur | Regex | Dans un scénario de détection, la vitesse prime ; les regex offrent une meilleure couverture des variantes/contournements |
| Premier signalé vs détection complète | Détection complète | Une entrée peut déclencher simultanément plusieurs types d'attaques, aucune ne doit être manquée |
| Zéro dépendance vs introduction de serde | Zéro dépendance | Dépend uniquement de `regex`, compilation rapide et taille réduite |

---

## Architecture

```
                       ┌──────────────────────────────────┐
                       │             Scanner              │
                       │  ┌────────────────────────────┐  │
    user input ───────►│  │ scan(input)                │  │      Vec<DetectionResult>
                       │  │ scan_with(input, &[...])   │──┼──►──────────────────────►
                       │  └─────────────┬──────────────┘  │
                       │                │                  │
                       │  ┌─────────────▼──────────────┐  │
                       │  │   Vec<Box<dyn Detector>>   │  │
                       │  │   ├─ XssDetector           │  │
                       │  │   ├─ SqlInjectionDetector  │  │
                       │  │   ├─ ... ×32               │  │
                       │  └────────────────────────────┘  │
                       └──────────────┬───────────────────┘
                                      │
       ┌──────────────────────────────┐
       │       Detector trait         │
       │  fn name(&self) -> &str      │
       │  fn detect(&self, &str)      │
       │       -> Option<Result>      │
       └──────────────┬───────────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
  ┌────┴────┐  ┌──────┴──────┐  ┌───┴────┐  ┌────┴────┐
  │injection│  │  protocol   │  │  data  │  │  file   │
  │  11 个  │  │   11 个     │  │ 7 个   │  │  3 个   │
  └─────────┘  └─────────────┘  └────────┘  └─────────┘
```

### Responsabilités des modules

| Module | Chemin | Nombre de détecteurs | Rôle |
|------|------|---------|------|
| Noyau | `src/lib.rs` `result.rs` `scanner.rs` | — | Trait `Detector`, `DetectionResult`, `Scanner`/`ScannerBuilder` |
| Injection | `src/injection/` | 11 | XSS, injection SQL, injection de commandes, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI, chaîne de format |
| Protocole | `src/protocol/` | 11 | SSRF, XXE, injection d'en-têtes, attaque de l'en-tête Host, contrebande de requêtes, redirection ouverte, CORS, WebSocket, DNS rebinding, Log4Shell, pollution de paramètres HTTP |
| Données | `src/data/` | 7 | Désérialisation PHP, injection de formules CSV, injection d'en-têtes de courriel, attaques JWT, pollution des prototypes, injection de formules, ReDoS |
| Fichiers | `src/file/` | 3 | Traversée de chemins, téléversement de fichiers malveillants, fuite de données sensibles |

### Structure du résultat de détection

`DetectionResult` renvoie de manière structurée six champs : `attack_type`, `category`, `severity`, `matched_pattern`, `offset`, `message`. La définition complète figure dans la [Référence API](./API.md).

---

## Fonctionnalités implémentées

### Attaques par injection (11 détecteurs)

| Détecteur | Motifs couverts | Sévérité |
|--------|---------|--------|
| **xss** | `<script>`, gestionnaires d'événements tels que `onerror=`, pseudo-protocole `javascript:`, balises `<svg>`/`<iframe>`, CSS `expression()`, `eval()`, `document.cookie` | Critical |
| **sql_injection** | `UNION SELECT`, injections à retard `sleep()`/`benchmark()`/`pg_sleep()`, énumération `information_schema`, procédures stockées `exec sp_`/`xp_`, motif d'aveugle booléen `' OR '1'='1`, `LOAD_FILE()`/`INTO OUTFILE` | Critical |
| **command_injection** | Commandes par backquote, sous-commandes `$()`, enchaînement par pipe, shell rebondi `/dev/tcp`, fonctions PHP `passthru()`/`shell_exec()`/`system()`, appels `cmd.exe`/`powershell` | Critical |
| **nosql_injection** | Opérateurs MongoDB `$ne`/`$gt`/`$regex`/`$where`, injection `$or`, contournement d'authentification `{"$gt": ""}` | Critical |
| **ldap_injection** | Opérateurs de filtre `(&` `(|` `(!`, énumération d'attributs `*(cn=`, injection `objectClass`/`uid` | High |
| **xpath_injection** | Contournement booléen `' or '1'='1`, injection de fonction `' or true()`, parcours de nœuds `'] | '` | High |
| **jndi_injection** | `${jndi:ldap://`, obfuscation `${lower:j}`, obfuscation `${upper:j}`, obfuscation par chaîne vide `${::-j}`, recherche de variable d'environnement `${env:}`, propriétés système `${sys:}` | Critical |
| **ssi_injection** | Exécution de commande `<!--#exec cmd=`, inclusion de fichier `<!--#include file=`, sortie de variable `<!--#echo var=`, informations de fichier `<!--#fsize`/`<!--#flastmod` | High |
| **graphql_injection** | Requêtes d'introspection `__schema`/`__type`, DoS par imbrication profonde (≥ 5 niveaux) | Medium |
| **ssti** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<%=` `<%@`, Velocity `#set()`, évasion de sandbox Python via MRO `__mro__`/`__subclasses__()` | Critical |
| **format_string** | spécificateurs d'écriture `%n` (y compris avec modificateurs de longueur), largeurs démesurées `%123456d`, spécificateurs `%x`/`%p`/`%s` répétés (fuite de chaîne de format / corruption mémoire) | Medium |

### Attaques par protocole et requêtes (11 détecteurs)

| Détecteur | Motifs couverts | Sévérité |
|--------|---------|--------|
| **ssrf** | Métadonnées cloud `169.254.169.254`, IP internes RFC1918 (10.x, 172.16-31.x, 192.168.x), loopback `127.x`, loopback IPv6 `::1`, `0.0.0.0`, protocoles dangereux `gopher://`/`dict://`/`ftp://`/`file://` | Critical |
| **xxe** | Déclaration d'entité `<!ENTITY`, références externes `SYSTEM`/`PUBLIC`, entités paramètres `%`, déclaration DTD `<!DOCTYPE` | Critical |
| **header_injection** | CRLF encodé en URL `%0d%0a`, injection CRLF brute `\r\n` | High |
| **host_header** | Injection de plusieurs en-têtes Host, empoisonnement `X-Forwarded-Host`/`X-Original-URL`/`X-Rewrite-URL`, Host avec CRLF | High |
| **request_smuggling** | Doubles en-têtes `Transfer-Encoding`, contrebande `Content-Length: 0`, confusion de terminaison chunked `\r\n0\r\n` | High |
| **open_redirect** | URL relative à protocole `//evil.com`, redirection par pseudo-protocole `javascript:`/`data:text/html` | Medium |
| **cors** | Contournement `Origin: null`, combinaison `Access-Control-Allow-Origin: *` + Credentials | Medium |
| **websocket** | Poignée de main `Upgrade: websocket`, WS interdomaines `Origin: null`, connexion en clair `ws://` | High |
| **dns_rebinding** | En-tête Host vers IP internes `127.x`/`10.x`/`192.168.x`/`172.16-31.x`, `localhost`, `::1`, `0.0.0.0` | High |
| **log4shell** | obfuscation de lookup `${lower:j}`/`${upper:j}`, obfuscation par chaîne vide `${::-j}`, lookups imbriqués `${${...}:...}`, variante encodée en URL `%24%7b...%7d...ndi` | Critical |
| **hpp** | mélange de séparateurs dans la chaîne de requête `&a=1;b=2` et `;a=1&b=2` (pollution de paramètres par divergence d'analyseurs) | Medium |

### Attaques de données et sérialisation (7 détecteurs)

| Détecteur | Motifs couverts | Sévérité |
|--------|---------|--------|
| **deserialization** | Objets sérialisés PHP `O:chiffre:`/`C:chiffre:`, tableaux `a:chiffre:{`, appels `unserialize()`, méthodes magiques `__wakeup`/`__destruct`/`__toString` | Critical |
| **csv_injection** | Caractères de formule en début de ligne `=`/`+`/`-`/`@`, échange de données dynamique DDE, pipe de commande `cmd|`, fonction `@SUM()` | Medium |
| **mail_header** | Injection en copie cachée `Bcc:`/`Cc:`, expéditeurs multiples `From:`, injection d'en-têtes MIME `MIME-Version:`/`Content-Type: multipart`, manipulation de limite `boundary=` | Medium |
| **jwt_attack** | Contournement par algorithme vide `alg: none`, injection de traversée de chemins `kid`, segment de signature vide, segment de payload vide | High |
| **prototype_pollution** | Pollution de chaîne de prototypes `__proto__`/`constructor.prototype`, détournement de propriétés `__defineGetter__`/`__defineSetter__`/`__lookupGetter__`/`__lookupSetter__` | High |
| **formula_injection** | caractères de formule en début de champ avec pipe de commande `=cmd|`, fonctions de tableur dangereuses `HYPERLINK`/`IMPORTXML`/`IMPORTDATA`/`IMPORTRANGE`/`WEBSERVICE`/`RTD`/`EXEC`, exfiltration via `|` + référence de cellule `A0`, appels `DDE(`, fonctions `@` | High |
| **redos** | retour arrière catastrophique : quantificateurs imbriqués `(a+)+`/`(a{2,})+`, alternatives qui se chevauchent `(a|ab)+`, quantificateur sur un groupe `\w`/`\d`/`.` | Medium |

### Fichiers et données sensibles (3 détecteurs)

| Détecteur | Motifs couverts | Sévérité |
|--------|---------|--------|
| **path_traversal** | Remontée de répertoire `../`/`..\\`, contournement par encodage URL `%2e%2e`, wrappers de protocole `php://filter`/`php://input`/`phar://`/`zip://`/`data://`/`expect://`/`glob://`, troncature par octet nul `%00` | Critical |
| **upload** | Balises PHP `<?php`/`<?=`, balises ASP `<%@`/`<%=`, motifs de backdoor `eval($_`/`system($_`/`exec($_`/`passthru($_`, superglobales `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`, contournement par encodage `base64_decode()` | Critical |
| **data_leak** | PAN de carte de crédit à 16 chiffres (Visa/MasterCard/AmEx/Discover/JCB/Diners), clés d'accès AWS `AKIA...`, en-têtes de clé privée PEM `-----BEGIN`, clés API OpenAI/LLM `sk-...`, chaînes de connexion de base de données `mongodb://`/`mysql://`/`postgresql://`/`redis://`/`jdbc:`, jeton JWT | Critical |

---

## Modules à état

`session`, `throttle` et `score` ne sont **pas** des implémentations de `Detector`. `session` et `throttle` sont à état et liés à une identité — `Detector::detect(&self, input: &str)` ne peut pas exprimer une entrée composite faite de jeton, d'empreinte, de position et de temps. Ils se placent donc à côté de la chaîne de détecteurs, pas dedans.

| Module | Type | Rôle |
|------|------|------|
| `session` | `SessionGuard<S: SessionStore>` | Sécurité de session : détournement de client, altération de données, connexion depuis un lieu inhabituel, sessions à jeton. Méthodes `bind`/`verify`/`revoke`/`revoke_all`/`rotate` ; `Decision { Allow, Challenge, Block }` + `SessionThreat` ; `SessionConfig` (`ttl_secs` 3600, `impossible_travel_kmh` 900.0, `timestamp_skew_secs` 300) ; trait `SessionStore` + `MemoryStore` |
| `throttle` | `Throttle<S: ThrottleStore>` | Limitation de débit et bannissement : fenêtre glissante, bannissement par seuil, verrouillage de compte. Méthodes `check`/`record_failure`/`record_success`/`reset`/`purge_expired` ; `ThrottleDecision { Allow { remaining }, Banned { until }, Unavailable }` ; `ThrottleConfig` (`threshold` 5, `window_secs` 60, `ban_secs` 900) |
| `score` | `RiskLevel`, `RiskAssessment`, `Scanner::assess()` | Évaluation du risque : agrège des signaux isolés de faible gravité en une grandeur mesurable. `RiskLevel { None, Low, Medium, High, Critical }` |

**L'asymétrie en cas de panne est volontaire.** `SessionGuard` renvoie `Decision::Block` (`StoreUnavailable`) si le stockage défaille — fail-closed, jamais de passage. `Throttle` est l'exception assumée : la limitation de débit relève de la défense en profondeur et non d'une barrière d'authentification principale ; une panne du backend renvoie donc `ThrottleDecision::Unavailable` et non `Banned` — bloquer tout le monde serait un auto-DoS. La décision appartient à l'appelant.

**Toujours aucune nouvelle dépendance :** la liste se limite à `regex`. Le prix à payer : le jeton et la signature sont fournis par l'appelant, les positions sont analysées par l'appelant. Les deux modules abstrayent leur stockage derrière un trait — pour un déploiement multi-instances, il suffit d'implémenter `SessionStore`/`ThrottleStore` sur Redis.

---

## Guide d'utilisation

Utilisable sans aucune configuration :

```rust
use security_rust::Scanner;

let scanner = Scanner::default();
let results = scanner.scan("<script>alert('xss')</script>");
// [CRITICAL] XSS cross-site scripting detected — offset: 0, pattern: <script>
```

La référence API complète (installation, scan sélectif, configuration personnalisée, affichage de la sévérité, performances) figure dans la [Référence API](./API.md).

---

## Développement

```bash
# Construction
cargo build --release

# Tests (462 tests : 354 unitaires, 46 d'intégration, 62 de module)
cargo test

# Vérification du code
cargo clippy -- -D warnings
```

---

## Don / Soutien

Si ce projet vous est utile, vous êtes invités à le soutenir par un don (facultatif).

| Alipay | WeChat Pay |
|--------|---------|
| ![Alipay](alipay.png) | ![WeChat Pay](weixinpay.png) |

### Virement international

【Informations du bénéficiaire】
- Nom du bénéficiaire : WANG KEXUN
- Numéro de compte du bénéficiaire : 881015918251

【Banque du bénéficiaire】
- SWIFT Code de ZA Bank : AABLHKHHXXX
- Nom de la banque : ZA Bank Limited
- Numéro de banque : 387
- Adresse de la banque : Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【Banque correspondante pour virements transfrontaliers (si nécessaire)】

Veuillez noter qu'il s'agit des informations de la banque correspondante (banque intermédiaire) pour les virements transfrontaliers, et non de la banque du bénéficiaire. Veuillez demander à votre banque d'origine si les informations de la banque correspondante pour virements transfrontaliers sont requises.

Pour les virements en dollars de Hong Kong, en renminbi et en dollars américains, la banque correspondante est Citibank :
- Nom de la banque : Citibank N.A. Hong Kong
- SWIFT Code : CITIHKHXXXX
- Numéro de banque : 006
- Nom de l'agence : Hong Kong Branch
- Numéro d'agence : 391
- Adresse de la banque : Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

Pour les virements dans d'autres devises, la banque correspondante est BNY Mellon :
- Nom de la banque : THE BANK OF NEW YORK MELLON
- SWIFT Code : IRVTUS3NXXX
- Adresse de la banque : THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## Licence

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
