# StruLink API Reference

Complete API documentation for StruLink.

## Table of Contents

- [Validation Methods](#validation-methods)
- [Encoding/Decoding Methods](#encodingdecoding-methods)
- [Security Methods](#security-methods)
- [Analysis Methods](#analysis-methods)
- [Utility Methods](#utility-methods)

---

## Validation Methods

### `checkUrl(url: string, options?: CheckUrlOptions)`

Synchronously validates a URL with customizable options.

**Parameters:**
- `url` (string): The URL to validate
- `options` (object, optional):
  - `literalValue` (string): Expected literal value
  - `detectMaliciousPatterns` (boolean): Enable malicious pattern detection
  - `httpsOnly` (boolean): Require HTTPS protocol
  - `allowInternationalChars` (boolean): Allow international characters

**Returns:** `CheckUrlResult`

**Example:**
```typescript
const result = __strl__.checkUrl("https://example.com", {
  httpsOnly: true,
  detectMaliciousPatterns: true
});
console.log(result.isValid); // true/false
```

---

### `asyncCheckUrl(url: string, options?: CheckUrlOptions)`

Asynchronously validates a URL (non-blocking).

**Returns:** `Promise<CheckUrlResult>`

**Example:**
```typescript
const result = await __strl__.asyncCheckUrl("https://example.com");
```

---

### `isValidUri(url: string, options?: ValidationOptions)`

Quick URI validation check.

**Returns:** `boolean`

**Example:**
```typescript
const isValid = __strl__.isValidUri("https://example.com");
```

---

## Encoding/Decoding Methods

### `encode(input: string, encodingType: ENC_TYPE)`

Encodes a string using the specified encoding type.

**Parameters:**
- `input` (string): String to encode
- `encodingType` (ENC_TYPE): Encoding type (e.g., "base64", "percentEncoding")

**Returns:** `string`

**Example:**
```typescript
const encoded = __strl__.encode("Hello World", "base64");
// Returns: "SGVsbG8gV29ybGQ="
```

---

### `decode(input: string, encodingType: DEC_FEATURE_TYPE)`

Decodes a string using the specified encoding type.

**Returns:** `DecodedResult`

**Example:**
```typescript
const decoded = __strl__.decode("SGVsbG8gV29ybGQ=", "base64");
console.log(decoded.val()); // "Hello World"
```

---

### `autoDetectAndDecode(input: string, maxIterations?: number)`

Automatically detects encoding and decodes the input.

**Parameters:**
- `input` (string): Encoded string
- `maxIterations` (number, optional): Maximum decode iterations (default: 10)

**Returns:** `DecodedResult`

**Example:**
```typescript
const decoded = __strl__.autoDetectAndDecode("https://example.com?data=SGVsbG8=");
```

---

### `asyncAutoDetectAndDecode(input: string, maxIterations?: number)`

Async version of auto-detect and decode.

**Returns:** `Promise<DecodedResult>`

---

### `detectEncoding(input: string, depth?: number)`

Detects the encoding type of a string.

**Parameters:**
- `input` (string): String to analyze
- `depth` (number, optional): Detection depth for nested encodings

**Returns:** `EncodingDetectionResult`

**Example:**
```typescript
const detection = __strl__.detectEncoding("hello%20world");
console.log(detection.mostLikely); // "percentEncoding"
console.log(detection.confidence); // 0.95
```

---

## Security Methods

### `detectMaliciousPatterns(input: string, options?: MaliciousPatternOptions)`

Detects malicious patterns in URLs or strings.

**Parameters:**
- `input` (string): URL or string to analyze
- `options` (object, optional):
  - `sensitivity` (number): Detection sensitivity (0-1)
  - `minScore` (number): Minimum threat score threshold

**Returns:** `MaliciousPatternResult`

**Example:**
```typescript
const result = __strl__.detectMaliciousPatterns(
  "https://example.com?user=admin' OR '1'='1",
  { sensitivity: 1.0 }
);
console.log(result.isMalicious); // true
console.log(result.patterns); // Array of detected patterns
```

---

### `scanUrl(url: string)`

Comprehensive URL security scan.

**Returns:** `UrlScanReport`

**Example:**
```typescript
const report = __strl__.scanUrl("https://example.com?user=<script>");
console.log(report.threats); // Array of detected threats
console.log(report.recommendations); // Security recommendations
```

---

### `sanitizeInput(input: string, options?: SanitizeOptions)`

Sanitizes potentially malicious input.

**Returns:** `string`

**Example:**
```typescript
const clean = __strl__.sanitizeInput("<script>alert('xss')</script>");
```

---

## Analysis Methods

### `analyzeURL(url: string)`

Analyzes URL structure and parameters.

**Returns:** `UrlAnalysis`

**Example:**
```typescript
const analysis = __strl__.analyzeURL("https://example.com/path?key=value");
console.log(analysis.params); // { key: { value: "value", risks: [...] } }
```

---

### `needsDeepScan(input: string)`

Determines if input requires deep security scanning.

**Returns:** `boolean`

**Example:**
```typescript
const needsScan = __strl__.needsDeepScan("https://example.com?user=<script>");
console.log(needsScan); // true
```

---

## Utility Methods

### `createUrl(uri: string)`

Creates a URL object from a URI string.

**Returns:** `URL`

**Example:**
```typescript
const url = __strl__.createUrl("https://example.com/path");
console.log(url.pathname); // "/path"
```

---

### `generateWAFBypassVariants(input: string)`

Generates encoding variants for WAF bypass testing.

**Returns:** `Record<string, string>`

**Example:**
```typescript
const variants = __strl__.generateWAFBypassVariants("<script>");
// Returns: { percent: "%3Cscript%3E", base64: "PHNjcmlwdD4=", ... }
```

---

## Types

### `CheckUrlResult`

```typescript
interface CheckUrlResult {
  isValid: boolean;
  url?: string;
  errors?: string[];
  warnings?: string[];
  maliciousPatterns?: DetectedPattern[];
}
```

### `DecodedResult`

```typescript
interface DecodedResult {
  val(): string;
  encodingType?: string;
  confidence?: number;
}
```

### `EncodingDetectionResult`

```typescript
interface EncodingDetectionResult {
  mostLikely: string;
  confidence: number;
  nestedTypes: string[];
}
```

### `MaliciousPatternResult`

```typescript
interface MaliciousPatternResult {
  isMalicious: boolean;
  score: number;
  patterns: DetectedPattern[];
  recommendations: string[];
}
```

---

[← Back to README](../README.md)
