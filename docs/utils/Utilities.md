# General Utilities

StruLink exports specific granular functions independently of the `StruLink` core instance for convenience and lightweight implementations.

## `decodeB64`

Extracts and validates Base64 payloads securely without requiring invocation of the iterative `autoDetectAndDecode` scanner.

```typescript
import { decodeB64 } from "strulink";

const payload = "ZmFsc2U=";
const plaintext = decodeB64(payload); // -> 'false'
```

## `detectDuplicateUrlParams`

Examines URL queries specifically hunting for Parameter Pollution variables, a common vector utilized for manipulating backend parsers.

```typescript
import { detectDuplicateUrlParams } from "strulink";

const evaluation = detectDuplicateUrlParams(
  "https://api.example.com?auth=admin&auth=user",
);
// evaluation.duplicatedKeys -> ['auth']
// evaluation.duplicatedValues -> ['admin', 'user']
```
