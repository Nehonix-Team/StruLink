# Encoding Types Reference

Complete list of all encoding types supported by StruLink.

## Supported Encodings

### URL/Percent Encoding

- **`percentEncoding`** / **`url`**
  - Standard URL percent encoding
  - Example: `hello world` → `hello%20world`

- **`doublepercent`**
  - Double percent encoding
  - Example: `hello world` → `hello%2520world`

### Base Encodings

- **`base64`**
  - Standard Base64 encoding
  - Example: `Hello World` → `SGVsbG8gV29ybGQ=`

- **`urlSafeBase64`**
  - URL-safe Base64 (- and _ instead of + and /)
  - Example: `Hello World` → `SGVsbG8gV29ybGQ=`

- **`base32`**
  - Base32 encoding
  - Example: `Hello` → `JBSWY3DP`

### Hexadecimal Encodings

- **`hex`** / **`hexadecimal`**
  - Hexadecimal encoding
  - Example: `Hello` → `48656c6c6f`

- **`asciihex`**
  - ASCII hexadecimal encoding
  - Example: `Hello` → `\x48\x65\x6c\x6c\x6f`

- **`rawHexadecimal`**
  - Raw hex without delimiters
  - Example: `Hello` → `48656C6C6F`

### Octal Encoding

- **`asciioct`**
  - ASCII octal encoding
  - Example: `Hello` → `\110\145\154\154\157`

### Character Encodings

- **`unicode`**
  - Unicode escape sequences
  - Example: `Hello` → `\u0048\u0065\u006c\u006c\u006f`

- **`htmlEntity`** / **`html`**
  - HTML entity encoding
  - Example: `<script>` → `&lt;script&gt;`

- **`decimalHtmlEntity`**
  - Decimal HTML entities
  - Example: `<` → `&#60;`

- **`punycode`**
  - Punycode for internationalized domain names
  - Example: `münchen` → `mnchen-3ya`

### Escape Encodings

- **`jsEscape`**
  - JavaScript string escaping
  - Example: `Hello"World` → `Hello\"World`

- **`cssEscape`**
  - CSS string escaping
  - Example: `Hello"World` → `Hello\22 World`

### Other Encodings

- **`rot13`**
  - ROT13 cipher
  - Example: `Hello` → `Uryyb`

- **`utf7`**
  - UTF-7 encoding
  - Example: `Hello` → `Hello`

- **`quotedPrintable`**
  - Quoted-printable encoding
  - Example: `Hello=World` → `Hello=3DWorld`

- **`jwt`**
  - JSON Web Token decoding
  - Decodes JWT tokens

## Usage Examples

### Encoding

```typescript
import { __strl__ } from "strulink";

// Base64
const b64 = __strl__.encode("Hello World", "base64");
// "SGVsbG8gV29ybGQ="

// Percent encoding
const percent = __strl__.encode("hello world", "percentEncoding");
// "hello%20world"

// Hex
const hex = __strl__.encode("Hello", "hex");
// "48656c6c6f"
```

### Decoding

```typescript
// Base64
const decoded = __strl__.decode("SGVsbG8gV29ybGQ=", "base64");
console.log(decoded.val()); // "Hello World"

// Percent encoding
const decoded2 = __strl__.decode("hello%20world", "percentEncoding");
console.log(decoded2.val()); // "hello world"
```

### Auto-Detection

```typescript
// Automatically detects and decodes
const result = __strl__.autoDetectAndDecode("SGVsbG8gV29ybGQ=");
console.log(result.val()); // "Hello World"

// Get detection info
const detection = __strl__.detectEncoding("hello%20world");
console.log(detection.mostLikely); // "percentEncoding"
console.log(detection.confidence); // 0.95
```

### Nested Encoding

StruLink can detect and decode nested encodings:

```typescript
// Double-encoded: Base64 of percent-encoded string
const nested = "aGVsbG8lMjB3b3JsZA==";
const result = __strl__.autoDetectAndDecode(nested);
console.log(result.val()); // "hello world"
```

## Detection Capabilities

StruLink automatically detects:

- Single encodings
- Nested/multiple encodings (up to configurable depth)
- Mixed encodings in URLs
- Confidence scores for each detection

## Encoding Type Constants

```typescript
import { ENC_TYPE, DEC_FEATURE_TYPE } from "strulink";

// For encoding
__strl__.encode(input, ENC_TYPE.BASE64);
__strl__.encode(input, ENC_TYPE.PERCENT_ENCODING);

// For decoding
__strl__.decode(input, DEC_FEATURE_TYPE.BASE64);
__strl__.decode(input, DEC_FEATURE_TYPE.PERCENT_ENCODING);
```

---

[← Back to README](../README.md) | [API Reference](./API.md)
