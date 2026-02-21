# StruLink

> **⚠️ DEPRECATION NOTICE**
> 
> **[NehonixURIProcessor](https://github.com/nehonix/nehonixUriProcessor) will be deprecated in December 2025.**
> 
> This is the **official successor** - a simplified, refocused version with:
> - ✅ Pure URL/URI and String encoding, decoding, validation utilities
> - ✅ Zero framework dependencies (no Express/React)
> - ✅ Lightweight (only 1 dependency)
> - ❌ Removed: AI/ML features, Python microservices, framework integrations
> 
> **Migration**: If you need Express/React integrations or ML features, continue using [nehonix/nehonixUriProcessor](https://github.com/nehonix/nehonixUriProcessor) until December 2025. Otherwise, migrate to StruLink now.

---

A focused TypeScript library for URL/URI and String encoding, decoding, validation, and parsing. Designed for developers who need powerful URL manipulation utilities without framework dependencies.

[![npm version](https://img.shields.io/npm/v/strulink.svg)](https://www.npmjs.com/package/strulink)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Version**: 1.0.0  
**License**: MIT  
**Repository**: [github.com/Nehonix-Team/StruLink](https://github.com/Nehonix-Team/StruLink)

## Quick Start

### Installation

```bash
npm install strulink
# or
bun add strulink
# or
yarn add strulink
```

### Basic Usage

```typescript
import { StruLink as __strl__ } from "strulink";

// Validate and decode URL
const result = await __strl__.asyncCheckUrl("https://example.com?data=SGVsbG8=");
console.log(result.isValid); // true

// Auto-detect and decode
const decoded = __strl__.autoDetectAndDecode("https://example.com?data=SGVsbG8gV29ybGQ=");
console.log(decoded); // https://example.com?data=Hello World

// Detect malicious patterns
const analysis = __strl__.detectMaliciousPatterns("https://example.com?user=admin' OR '1'='1");
console.log(analysis.isMalicious); // true
```

## Features

- **🔍 URL Validation**: Validate URIs with customizable rules
- **🔓 Auto-Detection & Decoding**: Decode complex URI encodings automatically
- **🎨 Multiple Encodings**: Base64, percent encoding, hex, punycode, JWT, and more
- **🛡️ Security Analysis**: Detect SQL injection, XSS, path traversal patterns
- **🌐 Internationalized URIs**: Full punycode support
- **⚡ Lightweight**: Only 1 runtime dependency
- **📦 Zero Config**: Works out of the box

## Supported Encoding Types

`percentEncoding` • `base64` • `hex` • `unicode` • `htmlEntity` • `punycode` • `asciihex` • `asciioct` • `rot13` • `base32` • `urlSafeBase64` • `jsEscape` • `cssEscape` • `utf7` • `quotedPrintable` • `jwt` • and more

## Documentation

📚 **[Full Documentation](./docs/web/index.html)** - Complete API reference and guides

### Quick Links

- [API Reference](./docs/API.md) - Detailed method documentation
- [Encoding Guide](./docs/ENCODING.md) - All supported encoding types
- [Security Features](./docs/SECURITY.md) - Security analysis and pattern detection
- [Examples](./docs/EXAMPLES.md) - Common use cases and code samples
- [Migration Guide](./docs/MIGRATION.md) - Migrating from NehonixURIProcessor

## Core API

```typescript
// Validation
__strl__.checkUrl(url, options)
__strl__.asyncCheckUrl(url, options)
__strl__.isValidUri(url, options)

// Encoding/Decoding
__strl__.encode(input, encodingType)
__strl__.decode(input, encodingType)
__strl__.autoDetectAndDecode(input)
__strl__.detectEncoding(input)

// Security
__strl__.detectMaliciousPatterns(input, options)
__strl__.scanUrl(url)
__strl__.sanitizeInput(input)

// Analysis
__strl__.analyzeURL(url)
__strl__.needsDeepScan(input)
```

## Why StruLink?

| Feature | StruLink | NehonixURIProcessor |
|---------|----------|---------------------|
| URL Encoding/Decoding | ✅ | ✅ |
| Security Analysis | ✅ | ✅ |
| Framework Integrations | ❌ | ✅ (Express/React) |
| AI/ML Features | ❌ | ✅ |
| Dependencies | 1 | 12+ |
| Bundle Size | ~50KB | ~2MB+ |
| Status | ✅ Active | ⚠️ Deprecated Dec 2025 |

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) first.

## License

MIT © [Nehonix Team](https://nehonix.space)

## Links

- [GitHub](https://github.com/Nehonix-Team/StruLink)
- [npm](https://www.npmjs.com/package/strulink)
- [Documentation](./docs/web/index.html)
- [Issues](https://github.com/Nehonix-Team/StruLink/issues)
- [Changelog](./docs/changelog.md)

---
