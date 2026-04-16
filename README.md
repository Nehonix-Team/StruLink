# StruLink

> **DEPRECATION NOTICE**
>
> **[NehonixURIProcessor](https://github.com/nehonix/nehonixUriProcessor) will be deprecated in December 2025.**
>
> StruLink is the official successor. It is a simplified, refocused version featuring:
>
> - Pure URL/URI and String encoding, decoding, and validation utilities.
> - A minimal footprint (only 1 runtime dependency).
> - Note: AI/ML features, Python microservices, and framework integrations have been removed.
>
> **Migration Plan**: If your project relies on Express/React integrations or machine learning features, continue using [nehonix/nehonixUriProcessor](https://github.com/nehonix/nehonixUriProcessor) until December 2025. For pure utility usage, migrate to StruLink.

---

StruLink is a focused TypeScript library for URL/URI and string encoding, decoding, validation, and parsing. It is designed for developers who require high-performance URL manipulation utilities without the overhead of framework dependencies.

[![npm version](https://img.shields.io/npm/v/strulink.svg)](https://www.npmjs.com/package/strulink)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


## Quick Start

### Installation

**Recommended for TypeScript projects:**

```bash
xfpm install strulink
```

Alternative methods:

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
const result = await __strl__.asyncCheckUrl(
  "https://example.com?data=SGVsbG8=",
);
console.log(result.isValid); // true

// Auto-detect and decode
const decoded = __strl__.autoDetectAndDecode(
  "https://example.com?data=SGVsbG8gV29ybGQ=",
);
console.log(decoded); // https://example.com?data=Hello World

// Detect malicious patterns
const analysis = __strl__.detectMaliciousPatterns(
  "https://example.com?user=admin' OR '1'='1",
);
console.log(analysis.isMalicious); // true
```

## Features

- **URL Validation**: Validate URIs against customizable rules.
- **Auto-Detection & Decoding**: Decode complex URI parameter encodings automatically.
- **Multiple Encodings Supported**: Base64, percent encoding, hex, punycode, JWT, and more.
- **Security Analysis**: Detect SQL injection, XSS, and path traversal patterns.
- **Internationalized URIs**: Complete punycode support.
- **Lightweight Architecture**: Single runtime dependency.
- **Zero Configuration**: Ready for use without additional setup.

## Supported Encoding Types

`percentEncoding` • `base64` • `hex` • `unicode` • `htmlEntity` • `punycode` • `asciihex` • `asciioct` • `rot13` • `base32` • `urlSafeBase64` • `jsEscape` • `cssEscape` • `utf7` • `quotedPrintable` • `jwt` • and more

## Documentation

**[Complete Documentation](./docs/readme.md)** - Main index for comprehensive API references and developer guides.

### Guide References

- [Core API Reference](./docs/api/StruLink.md) - Detailed method documentation for the `StruLink` class
- [Safety Layer](./docs/security/SafetyLayer.md) - Context-aware encoding instructions
- [Security Patterns](./docs/security/Patterns.md) - Threat intelligence and detection mechanisms
- [General Utilities](./docs/utils/Utilities.md) - Independent utility functions
- [Changelog](./docs/changelog.md) - Version history and updates

## Core API Reference

```typescript
// Validation
__strl__.checkUrl(url, options);
__strl__.asyncCheckUrl(url, options);
__strl__.isValidUri(url, options);

// Encoding and Decoding
__strl__.encode(input, encodingType);
__strl__.decode(input, encodingType);
__strl__.autoDetectAndDecode(input);
__strl__.detectEncoding(input);

// Security Analysis
__strl__.detectMaliciousPatterns(input, options);
__strl__.scanUrl(url);
__strl__.sanitizeInput(input);

// General Analysis
__strl__.analyzeURL(url);
__strl__.needsDeepScan(input);
```

## Contribution Guidelines

Contributions to the project are welcome. Please refer to our [Contributing Guide](./CONTRIBUTING.md) prior to submitting pull requests.

## License

MIT Copyright (c) [Nehonix Team](https://github.com/Nehonix-Team)

## Key Links

- [GitHub Repository](https://github.com/Nehonix-Team/StruLink)
- [NPM Package](https://www.npmjs.com/package/strulink)
- [Issue Tracker](https://github.com/Nehonix-Team/StruLink/issues)
- [Changelog](./docs/changelog.md)
