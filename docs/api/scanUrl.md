# `scanUrl` Method Reference

## Overview

`scanUrl` is the primary URL security scanning method exposed by `StruLink`. It performs a deep analysis of a URL and its components to identify potential malicious patterns, including injection attempts, SSRF, XSS, template injection, path traversal, open redirect vectors, and more.

The method is a thin wrapper over `NSS.analyzeUrl()` and returns a structured `MaliciousPatternResult` object containing detected issues, score, confidence, and remediation guidance.

## Signature

```ts
static scanUrl(
  url: string,
  options?: MaliciousPatternOptions,
): Promise<MaliciousPatternResult>
```

## Parameters

### `url`

- Type: `string`
- Description: The URL to analyze.

### `options`

- Type: `MaliciousPatternOptions`
- Description: Optional configuration settings that control which patterns are evaluated, how results are scored, and how the scanner behaves.

## Return Value

Returns a promise that resolves to a `MaliciousPatternResult` object.

### `MaliciousPatternResult`

Contains:

- `isMalicious`: `boolean` — whether the URL is considered malicious based on the configured minimum score.
- `detectedPatterns`: `DetectedPattern[]` — list of matched patterns with details.
- `score`: `number` — computed risk score.
- `confidence`: `"low" | "medium" | "high"` — overall confidence level.
- `recommendation`: `string` — remediation guidance.
- `contextAnalysis?`: optional detailed analysis metadata.

## `MaliciousPatternOptions`

### Core Options

| Option                      | Type                                                                  | Default                                                                  | Description                                                                                              |
| --------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------- |
| `minScore`                  | `number`                                                              | `50`                                                                     | Minimum score required to classify the URL as malicious.                                                 |
| `debug`                     | `boolean`                                                             | `false`                                                                  | Enables verbose logging for debugging detection behavior.                                                |
| `ignorePatterns`            | `MaliciousPatternType[]`                                              | `[]`                                                                     | List of built-in pattern categories to skip during scanning.                                             |
| `enabledPatternTypes`       | `MaliciousPatternType[]`                                              | `[]`                                                                     | If non-empty, only these pattern categories are evaluated. Overrides `ignorePatterns` behavior.          |
| `sensitivity`               | `number`                                                              | `1.0`                                                                    | Global sensitivity multiplier. Values > 1.0 increase detection aggressiveness; values < 1.0 decrease it. |
| `customPatterns`            | `Array<{ pattern: RegExp; type: MaliciousPatternType; severity: "low" | "medium"                                                                 | "high"; description: string; }>`                                                                         | `[]`    | Add developer-defined regular expressions to detect additional malicious payloads. |
| `patternOverrides`          | `PatternOverride[]`                                                   | `[]`                                                                     | Modify built-in detection sets by adding, removing, or replacing regex patterns.                         |
| `allowlist`                 | `AllowlistConfig`                                                     | Empty allowlist                                                          | Allowlist safe domains, hostnames, parameter names, parameter values, protocols, or TLDs.                |
| `enableContextualAnalysis`  | `boolean`                                                             | `true`                                                                   | Enable cross-pattern context analysis and relationship scoring.                                          |
| `enableEntropyAnalysis`     | `boolean`                                                             | `true`                                                                   | Enable high-entropy detection for obfuscated payloads.                                                   |
| `enableStatisticalAnalysis` | `boolean`                                                             | `true`                                                                   | Enable anomaly scoring based on character distribution.                                                  |
| `componentSensitivity`      | `Record<MaliciousComponentType, number>`                              | `{ protocol: 1.0, hostname: 1.2, path: 1.0, query: 1.5, fragment: 1.3 }` | Per-URL-component sensitivity multipliers.                                                               |
| `characterSet`              | `"latin"                                                              | "unicode"                                                                | "all"`                                                                                                   | `"all"` | Scope pattern matching to a specific character set.                                |
| `advanced`                  | `AdvancedDetectionConfig`                                             | Defaults shown below                                                     | Fine-tune detection behavior and scoring.                                                                |

> For the full list of available pattern categories, see [MaliciousPatternType](MaliciousPatternType.md).

## Nested Option Types

### `PatternOverride`

Use this to customize built-in pattern groups.

| Field     | Type                   | Description                                                |
| --------- | ---------------------- | ---------------------------------------------------------- |
| `type`    | `MaliciousPatternType` | The built-in pattern category to override.                 |
| `add`     | `RegExp[]`             | Additional regexes to append to the category.              |
| `remove`  | `RegExp[]`             | Regexes to remove from the category by exact string match. |
| `replace` | `RegExp[]`             | Replace the entire built-in category with these patterns.  |

### `AllowlistConfig`

Defines values that should be considered safe and excluded from scanning heuristics.

| Field                    | Type       | Description                                        |
| ------------------------ | ---------- | -------------------------------------------------- |
| `domains`                | `string[]` | Allowlist explicit domains.                        |
| `hostnames`              | `string[]` | Allowlist hostnames.                               |
| `parameterNames`         | `string[]` | Allowlist query parameter names.                   |
| `parameterValuePatterns` | `RegExp[]` | Allowlist parameter values matching these regexes. |
| `protocols`              | `string[]` | Allowlist allowed protocols.                       |
| `tlds`                   | `string[]` | Allowlist top-level domains.                       |

### `AdvancedDetectionConfig`

Fine-tune scanner internals for advanced use cases.

| Field                                     | Type                                            | Default                                                                                 | Description                                                              |
| ----------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------- | ------------------------------------------------- |
| `maxEncodingLayers`                       | `number`                                        | `5`                                                                                     | Max number of encoding rounds to detect when analyzing obfuscated input. |
| `entropyThreshold`                        | `number`                                        | `4.5`                                                                                   | Minimum entropy required to mark content as suspicious.                  |
| `scoring.severityScores`                  | `Partial<Record<"low"                           | "medium"                                                                                | "high", number>>`                                                        | `{ high: 40, medium: 20, low: 10 }`    | Custom score values for each severity tier.       |
| `scoring.confidenceMultipliers`           | `Partial<Record<"low"                           | "medium"                                                                                | "high", number>>`                                                        | `{ high: 1.5, medium: 1.0, low: 0.5 }` | Multipliers applied to score based on confidence. |
| `scoring.criticalPatternMultipliers`      | `Partial<Record<MaliciousPatternType, number>>` | `{ path_traversal: 1.5, server_side_request_forgery: 1.5, remote_file_inclusion: 1.5 }` | Extra multipliers for critical pattern categories.                       |
| `contextual.relatedPatternMultiplier`     | `number`                                        | `undefined`                                                                             | Custom multiplier used when related pattern groups are detected.         |
| `contextual.enableRelatedPatternGrouping` | `boolean`                                       | `undefined`                                                                             | Enable or disable related pattern grouping.                              |
| `anomaly.maxScore`                        | `number`                                        | `undefined`                                                                             | Maximum anomaly score used during statistical analysis.                  |

## Example Usage

### Basic URL Scan

```ts
import StruLink from "./src/StruLink";

const result = await StruLink.scanUrl(
  "https://example.com/login?next=https://evil.com",
);
console.log(result);
```

### Scan with Custom Patterns

```ts
const result = await StruLink.scanUrl(
  "https://example.com/test?payload=<script>alert(1)</script>",
  {
    customPatterns: [
      {
        pattern: /<script>[\s\S]*?<\/script>/i,
        type: "cross_site_scripting",
        severity: "high",
        description: "Custom script tag injection detection",
      },
    ],
  },
);
```

### Use Allowlist for Safe Parameters

```ts
const result = await StruLink.scanUrl(
  "https://example.com/api?token=abcd1234",
  {
    allowlist: {
      parameterNames: ["token"],
      parameterValuePatterns: [/^[A-Za-z0-9-_]{16,}$/],
    },
  },
);
```

### Advanced Tuning

```ts
const result = await StruLink.scanUrl(
  "https://example.com/redirect?url=https://example.com",
  {
    sensitivity: 0.8,
    advanced: {
      maxEncodingLayers: 3,
      entropyThreshold: 5.0,
      scoring: {
        severityScores: { high: 60, medium: 25, low: 10 },
        confidenceMultipliers: { high: 2.0, medium: 1.2, low: 0.6 },
      },
    },
  },
);
```

## Notes

- `scanUrl` performs component-level analysis and will separately evaluate protocol, hostname, path, query, and fragment values.
- `enabledPatternTypes` is useful when you want to limit scanning to a restricted set of threat categories.
- `patternOverrides` allow teams to tune built-in detection logic without modifying source patterns directly.
- If both `enabledPatternTypes` and `ignorePatterns` are set, `enabledPatternTypes` takes precedence by restricting the scanned categories to the listed types.

## Recommended Workflow

1. Use default options for broad URL scanning.
2. Add `customPatterns` for application-specific threat signatures.
3. Apply `allowlist` rules for known safe query parameters and domains.
4. Adjust `advanced` scoring only when you need finer control over risk thresholds.
