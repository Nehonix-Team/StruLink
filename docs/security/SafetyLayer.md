# Safety Layer (`__safeEncode__`)

The `__safeEncode__` function is a context-aware security encoder engineered to neutralize user input before rendering it in potentially vulnerable output states. It is critical for defending against injection vulnerabilities such as XSS, SQLi, and Command Injection.

## Usage

```typescript
import { __safeEncode__ } from "strulink";

const userInput = "<script>alert('pwned')</script>";
const safeHtml = __safeEncode__(userInput, "html");
```

## Signature

```typescript
function __safeEncode__(
  input: string,
  context: RWA_TYPES,
  options?: {
    doubleEncode?: boolean;
    encodeSpaces?: boolean;
    preserveNewlines?: boolean;
  },
): string;
```

## Supported Contexts (`RWA_TYPES`)

Proper defense requires matching the encoding context (`context` parameter) effectively with where the input will be rendered:

- **`html`**: Defenses against Standard XSS payload in HTML bodies via `htmlEntity` encode.
- **`htmlAttr`**: Applies `htmlEntity` context and forcefully replaces double quotes globally.
- **`js` / `jsString`**: Designed explicitly for escaping JavaScript strings. `jsString` enforces Unicode representations for maximum reliability.
- **`css` / `cssSelector`**: Exits CSS contexts smoothly. `cssSelector` specifically defends `: ` and `.`.
- **`url` / `urlParam`**: Applies `percentEncoding` or `urlSafeBase64` to prepare input for HTTP transfers.
- **`command`**: Ensures variables injected into shell arguments bypass critical operators `[&;'"\`\\|\*?~<>^()[]{}$\n\r\t#]`.
- **`xml` / `json`**: Framework-level compatibility conversions for XML properties and API-ready representations.

## Additional Options

- `doubleEncode`: Recommended `true` if WAF systems or backend frameworks natively trigger a decode sequentially before analysis.
- `preserveNewlines`: Retains the format specifically designed for standard `email` operations.
