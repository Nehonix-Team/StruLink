# `MaliciousPatternType` Enum Reference

`MaliciousPatternType` is the shared enumeration used throughout StruLink to classify detected malicious patterns. It is used by `scanUrl`, `detectMaliciousPatterns`, and custom pattern definitions.

## Usage

Use `MaliciousPatternType` values when:

- configuring `ignorePatterns`
- setting `enabledPatternTypes`
- defining `customPatterns`
- building rule sets or custom detection logic

## Enum Values

| Value                      | Description                                                       |
| -------------------------- | ----------------------------------------------------------------- |
| `SQL_INJECTION`            | SQL injection or database query manipulation attempts.            |
| `XSS`                      | Cross-site scripting payloads and script injection vectors.       |
| `COMMAND_INJECTION`        | Shell or command execution attempts in input.                     |
| `PATH_TRAVERSAL`           | File system traversal or unauthorized path access.                |
| `OPEN_REDIRECT`            | Redirect-based attacks that abuse URL parameters.                 |
| `SSRF`                     | Server-side request forgery attempts targeting internal services. |
| `CRLF_INJECTION`           | CRLF or header injection attacks.                                 |
| `ENCODED_PAYLOAD`          | Suspicious encoded content or obfuscated payloads.                |
| `SERIALIZATION`            | Serialization attack patterns and object injection.               |
| `TEMPLATE_INJECTION`       | Template engine injection vectors (SSTI).                         |
| `SUSPICIOUS_PARAMETER`     | Suspicious query parameter names or values.                       |
| `DATA_URI`                 | Dangerous data URI usage like inline HTML/JS payloads.            |
| `SUSPICIOUS_IP`            | Suspicious IP addresses used in URL parameters.                   |
| `SUSPICIOUS_TLD`           | Suspicious or uncommon top-level domains.                         |
| `SUSPICIOUS_DOMAIN`        | Suspicious or malicious domain names.                             |
| `PROTOCOL_CONFUSION`       | Mixed or unexpected protocol schemes.                             |
| `HOMOGRAPH_ATTACK`         | Unicode homograph or punycode domain spoofing.                    |
| `MULTI_ENCODING`           | Multi-layer encoded input or nested encoding.                     |
| `UNICODE_EVASION`          | Unicode-based evasion and character substitution.                 |
| `FRAGMENT_PAYLOAD`         | Payload split across URL fragments.                               |
| `HEADER_INJECTION`         | HTTP header injection attacks.                                    |
| `NOSQL_INJECTION`          | NoSQL-specific query injection attempts.                          |
| `GRAPHQL_INJECTION`        | GraphQL injection or query manipulation.                          |
| `DOM_BASED_ATTACK`         | DOM-based client-side attack vectors.                             |
| `FILE_INCLUSION`           | File inclusion payloads, remote/local.                            |
| `RFI`                      | Remote file inclusion attempts.                                   |
| `PHISHING`                 | Phishing-related URL patterns.                                    |
| `PROTOTYPE_POLLUTION`      | Prototype pollution payloads.                                     |
| `JWT_MANIPULATION`         | Manipulation of JWT or token content.                             |
| `CSS_INJECTION`            | CSS injection attack patterns.                                    |
| `HOST_HEADER_INJECTION`    | Host header injection attempts.                                   |
| `DESERIALIZATION`          | Deserialization vulnerabilities and unsafe payloads.              |
| `DOM_CLOBBERING`           | DOM clobbering or DOM attribute hijacking.                        |
| `CLICKJACKING`             | Clickjacking-related payloads or framing issues.                  |
| `CORS_MISCONFIGURATION`    | CORS misconfiguration indicators.                                 |
| `SUBDOMAIN_TAKEOVER`       | Potential subdomain takeover patterns.                            |
| `HTTP_PARAMETER_POLLUTION` | HTTP parameter pollution attacks.                                 |
| `WEB_CACHE_POISONING`      | Cache poisoning or HTTP cache abuse.                              |
| `ANOMALY`                  | General anomaly detection.                                        |
| `ZERO_DAY`                 | Zero-day or unknown high-risk threat signatures.                  |
| `RANSOMWARE`               | Ransomware-related payload signatures.                            |
| `SUSPICIOUS_BEHAVIOR`      | Behavior-based suspicious activity.                               |
| `PARAMETER_TAMPERING`      | Tampering of URL or query parameter values.                       |
| `HIGH_ENTROPY`             | High entropy content indicating obfuscation or encoded data.      |
| `KNOWN_THREAT`             | Known malicious indicators or threat signatures.                  |
| `RCE`                      | Remote code execution patterns.                                   |
| `ANOMALY_DETECTED`         | Detected anomaly or suspicious traffic.                           |
| `SUSPICIOUS_EXTENSION`     | Suspicious or dangerous file extension usage.                     |
| `KNOWN_MALICIOUS_URL`      | Known malicious URL fingerprint.                                  |

## Example

```ts
import { MaliciousPatternType } from "../services/MaliciousPatterns.service";

const result = await StruLink.scanUrl(url, {
  enabledPatternTypes: [MaliciousPatternType.SSRF, MaliciousPatternType.XSS],
});
```
