# StruLink Core API

The `StruLink` class (also available via the `__strl__` alias) is the central library interface containing key utilities for URL validation, encoding, decoding, and extensive security threat detection.

## Core Operations

### `generateWAFBypassVariants(input: string)`

Generates various encoded variants of an input string to test Web Application Firewall (WAF) resilience by obfuscating malicious payloads.

- **param** `input`: The string payload to encode.
- **returns**: An object where keys are the encoding types (`percent`, `base64`, etc.) and values are the obfuscated results.

### `analyzeURL(url: string, options?: MaliciousPatternOptions)`

Deeply analyzes a URL, parsing its components and extracting query parameters to evaluate them for security vulnerabilities like SQL injection or Cross-Site Scripting (XSS).

- **param** `url`: The full URL to analyze.
- **returns**: Detailed analysis containing components and risk evaluations per parameter.

### `encode(input: string, encodingType: ENC_TYPE)`

Encodes a string using explicit encoding methods.

- **param** `input`: String to format.
- **param** `encodingType`: One of the supported `ENC_TYPE` properties (e.g., `percentEncoding`, `base64`, `htmlEntity`).
- **returns**: The properly encoded payload.

### `decode(input: string, encodingType: ENC_TYPE | DEC_FEATURE_TYPE, maxRecursionDepth?: number)`

Decodes an encoded string corresponding to its target specification.

- **param** `input`: The encoded content to untangle.
- **param** `encodingType`: Expected decoding strategy to use.
- **param** `maxRecursionDepth`: Optional capability for nested decodings.

## Comprehensive URL Validation

### `isValidUri(url: string, options?: UrlValidationOptions): boolean`

### `checkUrl(url: string, options?: UrlValidationOptions): UrlCheckResult`

Performs comprehensive validation against custom criteria configurable via `UrlValidationOptions`. `checkUrl` provides extreme detail, while `isValidUri` returns a boolean response.

**Options snippet:**

- `strictMode`: Requires leading slashes before query params.
- `allowUnicodeEscapes`: Validates or blocks `\uXXXX` sequences.
- `rejectDuplicateParams`: Eliminates parameter duplication.
- `strictParamEncoding`: Ensures keys & values are properly URI-encoded.
- `requireProtocol`, `httpsOnly`, `allowedTLDs`.

## Intelligence and Detection

### `detectEncoding(input: string, depth?: number)`

Intelligently ascertains the encoding methodologies within an arbitrary string.

### `autoDetectAndDecode(input: string, maxIterations?: number)`

Detects the encoding schema automatically and fully decodes strings into plaintext utilizing an iterative approach until either plaintext or iteration limit is obtained.

### `detectMaliciousPatterns(input: string, options?: MaliciousPatternOptions): MaliciousPatternResult`

Comprehensive evaluation of plain text against the full scope of internal threat intelligence. Provides scores, confidences, classification of patterns (`DetectedPattern[]`), and remediation recommendations.

### `scanUrl(url: string, options?: MaliciousPatternOptions)`

Applies `detectMaliciousPatterns` intelligently over URL specific properties emphasizing URL-embedded paths and query properties.

### `sanitizeInput(input: string, options?: SanitizationOptions)`

Actively destructs and intercepts security risks within strings resulting in a safe string payload.

## Asynchronous Alternatives

- `asyncIsUrlValid`
- `asyncCheckUrl`
- `asyncAutoDetectAndDecode`
- `encodeMultipleAsync`
  Implement similar functionality asynchronously to free up the event loop in Node.js server architectures when computing heavy or long operations.
