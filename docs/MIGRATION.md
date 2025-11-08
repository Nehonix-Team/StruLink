# Migration Guide

Migrating from NehonixURIProcessor to StruLink.

## Overview

**NehonixURIProcessor will be deprecated in December 2025.** This guide helps you migrate to StruLink.

## Key Changes

### Package Name

```diff
- import { NehonixURIProcessor } from "nehonix-uri-processor";
+ import { StruLink } from "strulink";
```

### Alias

```diff
- import { __processor__ } from "nehonix-uri-processor";
+ import { __strl__ } from "strulink";
```

### Removed Features

StruLink focuses on core URL utilities. The following features were removed:

❌ **Express Middleware** - Use original library until December 2025  
❌ **React Hooks/Components** - Use original library until December 2025  
❌ **AI/ML Security Features** - Use original library until December 2025  
❌ **Python Microservices** - Not available  

✅ **Core URL encoding/decoding** - Fully supported  
✅ **URL validation** - Fully supported  
✅ **Security pattern detection** - Fully supported (non-ML)  
✅ **Multiple encoding support** - Fully supported  

## Migration Steps

### 1. Install StruLink

```bash
npm uninstall nehonix-uri-processor
npm install strulink
```

### 2. Update Imports

**Before:**
```typescript
import { 
  NehonixURIProcessor as __processor__,
  MaliciousPatternType 
} from "nehonix-uri-processor";
```

**After:**
```typescript
import { 
  StruLink as __strl__,
  MaliciousPatternType 
} from "strulink";
```

### 3. Update Method Calls

Most methods remain the same, just change the class name:

**Before:**
```typescript
const result = __processor__.checkUrl("https://example.com");
const decoded = __processor__.autoDetectAndDecode(input);
```

**After:**
```typescript
const result = __strl__.checkUrl("https://example.com");
const decoded = __strl__.autoDetectAndDecode(input);
```

## Feature Mapping

### Core Features (✅ Supported)

| NehonixURIProcessor | StruLink | Status |
|---------------------|----------|--------|
| `checkUrl()` | `checkUrl()` | ✅ Same |
| `asyncCheckUrl()` | `asyncCheckUrl()` | ✅ Same |
| `isValidUri()` | `isValidUri()` | ✅ Same |
| `encode()` | `encode()` | ✅ Same |
| `decode()` | `decode()` | ✅ Same |
| `autoDetectAndDecode()` | `autoDetectAndDecode()` | ✅ Same |
| `detectEncoding()` | `detectEncoding()` | ✅ Same |
| `detectMaliciousPatterns()` | `detectMaliciousPatterns()` | ✅ Same |
| `scanUrl()` | `scanUrl()` | ✅ Same |
| `analyzeURL()` | `analyzeURL()` | ✅ Same |

### Removed Features (❌ Not Supported)

| Feature | Alternative |
|---------|-------------|
| Express middleware | Continue using `nehonix-uri-processor` |
| React hooks/components | Continue using `nehonix-uri-processor` |
| `NehonixShieldProvider` | Not available |
| `useNehonixShield()` | Not available |
| AI/ML threat detection | Use pattern-based detection |
| Python microservices | Not available |

## Example Migration

### Before (NehonixURIProcessor)

```typescript
import { 
  NehonixURIProcessor as __processor__,
  nehonixShieldMiddleware 
} from "nehonix-uri-processor";
import express from "express";

const app = express();

// Express middleware (NOT AVAILABLE in StruLink)
app.use(nehonixShieldMiddleware({ blockOnMalicious: true }));

// Core functionality (AVAILABLE in StruLink)
const result = await __processor__.asyncCheckUrl("https://example.com");
const decoded = __processor__.autoDetectAndDecode(input);
```

### After (StruLink)

```typescript
import { StruLink as __strl__ } from "strulink";

// Core functionality - works the same
const result = await __strl__.asyncCheckUrl("https://example.com");
const decoded = __strl__.autoDetectAndDecode(input);

// For Express middleware, continue using nehonix-uri-processor
// until December 2025, then implement custom middleware using
// StruLink's core methods
```

## Custom Middleware Example

If you need Express middleware after migration:

```typescript
import { StruLink as __strl__ } from "strulink";
import { Request, Response, NextFunction } from "express";

function urlValidationMiddleware(req: Request, res: Response, next: NextFunction) {
  const url = req.url;
  
  const result = __strl__.detectMaliciousPatterns(url, { sensitivity: 1.0 });
  
  if (result.isMalicious) {
    return res.status(400).json({ 
      error: "Malicious URL detected",
      patterns: result.patterns 
    });
  }
  
  next();
}

app.use(urlValidationMiddleware);
```

## Breaking Changes

### 1. Package Name
- Old: `nehonix-uri-processor`
- New: `strulink`

### 2. Class Alias
- Old: `__processor__`
- New: `__strl__`

### 3. Dependencies
- Removed: `express`, `react`, `axios`, `chalk`, ML libraries
- Kept: Core URL processing only

### 4. Bundle Size
- Old: ~2MB+
- New: ~50KB

## Timeline

- **Now - November 2025**: Both libraries supported
- **December 2025**: NehonixURIProcessor deprecated
- **January 2026+**: Only StruLink maintained

## Need Help?

- [GitHub Issues](https://github.com/Nehonix-Team/StruLink/issues)
- [Documentation](./API.md)
- [Examples](./EXAMPLES.md)

---

[← Back to README](../README.md)
