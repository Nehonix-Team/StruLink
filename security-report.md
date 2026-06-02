# Rapport de Sécurité — StruLink URL Scanner
 
> Généré le **02/06/2026 11:31:46** · 83 cas testés · Taux de réussite global : **96.4%** 🟢
 
---
 
## Vue d'ensemble
 
| Métrique | Valeur |
|---|---|
| Total de tests | **83** |
| ✅ Réussis | **80** (96.4%) |
| 🟡 Faux Positifs (URL légitimes bloquées) | **🔴 3** |
| 🔴 Faux Négatifs (attaques non détectées) | **🟢 0** |
| 💥 Erreurs d'exécution | **0** |
 
> **Faux positifs** = URLs légitimes signalées à tort comme malveillantes → impact sur l'expérience développeur/utilisateur.  
> **Faux négatifs** = attaques réelles non détectées → risque de sécurité.
 
---
 
## Résultats par catégorie
 
| | Catégorie | Résultat | Taux | Faux Positifs | Faux Négatifs |
|---|---|---|---|---|---|
| ✅ | Command Injection | 4/4 | 100% | — | — |
| ✅ | CRLF Injection | 2/2 | 100% | — | — |
| 🟡 | False Positive Risk | 13/15 | 87% | 2 ⚠️ | — |
| ✅ | Legitimate - Auth | 2/2 | 100% | — | — |
| ✅ | Legitimate - Basic | 7/7 | 100% | — | — |
| ✅ | Legitimate - Encoding | 1/1 | 100% | — | — |
| ✅ | Legitimate - Production | 1/1 | 100% | — | — |
| 🟡 | Legitimate - Query strings | 5/6 | 83% | 1 ⚠️ | — |
| ✅ | Legitimate - Static assets | 2/2 | 100% | — | — |
| ✅ | Obfuscated | 4/4 | 100% | — | — |
| ✅ | Open Redirect | 3/3 | 100% | — | — |
| ✅ | Path Traversal | 5/5 | 100% | — | — |
| ✅ | Protocol Attack | 3/3 | 100% | — | — |
| ✅ | SQL Injection | 7/7 | 100% | — | — |
| ✅ | SSRF | 6/6 | 100% | — | — |
| ✅ | Template Injection | 4/4 | 100% | — | — |
| ✅ | XSS | 11/11 | 100% | — | — |
 
---
 
## Recommandations
 
### ⚠️ [HAUTE] Faux positifs — Legitimate - Query strings

1 URL légitimes bloquées à tort : Long but clean data URL. Affiner les regex pour éviter les collisions sur des sous-chaînes (ex: "transcript" vs "script", "evaluation" vs "eval").

### ⚠️ [HAUTE] Faux positifs — False Positive Risk

2 URL légitimes bloquées à tort : JWT token in query string, Localhost with long query string. Affiner les regex pour éviter les collisions sur des sous-chaînes (ex: "transcript" vs "script", "evaluation" vs "eval").

 
---
 
## Détail — Faux Positifs
 
| Label | Score | Patterns détectés | Note |
|---|---|---|---|
| Long but clean data URL | 100 | encoded_payload, encoded_payload | — |
| JWT token in query string | 100 | encoded_payload, suspicious_parameter, encoded_payload, suspicious_parameter | JWT passthrough is standard in some APIs |
| Localhost with long query string | 100 | suspicious_parameter, suspicious_parameter, multi_encoding | Dev debugging params |
 
---
 
## Détail — Faux Négatifs
 
_Aucun faux négatif détecté. ✅_
 
---
 
## Inventaire — URLs légitimes testées
 
Ces URLs doivent toutes passer **sans alerte** pour garantir une bonne expérience développeur dans Express.
 
| Statut | Label | Score | Patterns | Note |
|---|---|---|---|---|
| ✅ | Root path | 0 | — | — |
| ✅ | Simple API route | 0 | — | — |
| ✅ | REST resource with ID | 0 | — | — |
| ✅ | Nested REST route | 0 | — | — |
| ✅ | Query string - filters | 0 | — | — |
| ✅ | Query string - pagination | 0 | — | — |
| ✅ | Query string - search term with spaces encoded | 0 | — | — |
| ✅ | Query string - UUID param | 10 | suspicious_parameter | — |
| ✅ | URL with port | 0 | — | — |
| ✅ | HTTPS production URL | 0 | — | — |
| ✅ | URL with hash fragment | 0 | — | — |
| ✅ | File extension route | 0 | — | — |
| ✅ | Encoded accents in path (legitimate i18n) | 0 | — | Accented chars encoded correctly |
| ✅ | Kebab-case route with numbers | 0 | — | — |
| ✅ | Webhook callback URL | 0 | — | — |
| ✅ | OAuth redirect URI | 10 | suspicious_parameter | — |
| 🟡 FP | Long but clean data URL | 100 | encoded_payload, encoded_payload | — |
| ✅ | API key as query param (common pattern) | 24 | suspicious_parameter, suspicious_parameter | — |
| ✅ | URL with underscores and dots | 0 | — | — |
| ✅ | Template param name containing 'script' word | 0 | — | substring 'script' in legit word 'transcript' |
| ✅ | Route named 'execute' | 0 | — | exec-like word in route |
| ✅ | Query param 'select' | 0 | — | SQL keyword as legit GraphQL/REST field selector |
| ✅ | Query param 'union' (Hasura-style) | 0 | — | SQL keyword in legitimate GraphQL operation name |
| ✅ | Base64 encoded JSON in query param | 0 | — | Legit base64 state param, common in SPAs |
| 🟡 FP | JWT token in query string | 100 | encoded_payload, suspicious_parameter, encoded_payload, suspicious_parameter | JWT passthrough is standard in some APIs |
| ✅ | URL with 'eval' substring in legit word | 0 | — | substr 'eval' inside 'evaluation' |
| ✅ | URL with 'drop' in route name | 0 | — | SQL DROP keyword in legitimate product name |
| ✅ | URL with 'insert' as route | 0 | — | SQL keyword as REST verb in route |
| ✅ | Markdown-like content in query param | 24 | suspicious_parameter, suspicious_parameter | — |
| ✅ | URL with double slash in path (CDN common pattern) | 0 | — | Double slashes — path traversal false positive risk |
| 🟡 FP | Localhost with long query string | 100 | suspicious_parameter, suspicious_parameter, multi_encoding | Dev debugging params |
| ✅ | URL with percent-encoded parentheses (legitimate) | 0 | — | — |
| ✅ | Query param named 'callback' (JSONP legacy) | 10 | suspicious_parameter | JSONP pattern — not malicious by itself |
| ✅ | Path with 'admin' segment | 0 | — | Admin routes are legitimate |
 
---
 
## Erreurs d'exécution
 
_Aucune erreur d'exécution._
 
---
 
## Analyse des patterns déclencheurs
 
Les patterns ci-dessous ont déclenché le plus de faux positifs ou faux négatifs :
 
| Pattern | Occurrences dans les erreurs |
|---|---|
| `encoded_payload` | 4 |
| `suspicious_parameter` | 4 |
| `multi_encoding` | 1 |
 
---
 
## Recommandations pour patterns spécifiques
 
### Prévenir les faux positifs sur les sous-chaînes
 
Utiliser des **word boundaries** ou du contexte pour éviter les collisions :
 
```ts
// ❌ Trop large — va matcher "transcript", "description"…
/script/i
 
// ✅ Contextualisé — balises HTML uniquement
/(?:<|%3C)\s*script[\s>]/i
```
 
### Normalisation avant scan
 
```ts
function normalizeUrl(url: string): string {
  let decoded = url;
  // Double-decode URL encoding
  for (let i = 0; i < 3; i++) {
    try { decoded = decodeURIComponent(decoded); } catch { break; }
  }
  // HTML entity decode
  decoded = decoded
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&").replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
  // Unicode unescape
  decoded = decoded.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  return decoded;
}
```
 
### Détection IPs internes (SSRF)
 
```ts
function isPrivateIP(ip: string): boolean {
  // Decimal IP → convertir en notation classique
  if (/^\d+$/.test(ip)) {
    const n = parseInt(ip);
    const a = (n >> 24) & 255, b = (n >> 16) & 255;
    ip = `${a}.${b}.${(n >> 8) & 255}.${n & 255}`;
  }
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0)/.test(ip);
}
```
 
---
 
_Rapport généré automatiquement par `report-generator.ts` · StruLink Security Suite_
