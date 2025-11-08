/**
 * Encoding Detection Module (Working Version)
 * Handles automatic detection of encoding types with confidence scoring
 * 
 * Self-contained to avoid circular dependencies
 */

import { EncodingDetectionResult, ENC_TYPE } from "../../../types";

export class EncodingDetector {
  private static readonly MAX_DEPTH = 3;

  /**
   * Detect mixed encodings in a string
   */
  static detectMixedEncodings(input: string): string[] {
    const detectedEncodings = [];

    if (/%[0-9A-Fa-f]{2}/.test(input)) {
      detectedEncodings.push("percentEncoding");
    }

    const base64Regex = /[A-Za-z0-9+/=]{4,}/g;
    const potentialBase64 = input.match(base64Regex);
    if (potentialBase64) {
      for (const match of potentialBase64) {
        if (this.isBase64(match)) {
          detectedEncodings.push("base64");
          break;
        }
      }
    }

    if (/\\u[0-9A-Fa-f]{4}/.test(input)) {
      detectedEncodings.push("unicode");
    }

    if (/&[a-zA-Z]+;|&#[0-9]+;/.test(input)) {
      detectedEncodings.push("htmlEntity");
    }

    return detectedEncodings;
  }

  /**
   * Simple Base64 validation
   */
  private static isBase64(str: string): boolean {
    if (!str || str.length < 4) return false;
    const base64Regex = /^[A-Za-z0-9+/]+=*$/;
    return base64Regex.test(str) && str.length % 4 === 0;
  }

  /**
   * Detects the encoding type of an input string
   */
  static detectEncoding(
    input: string,
    depth: number = 0,
    utils: any
  ): EncodingDetectionResult {
    if (depth > this.MAX_DEPTH || !input || input.length < 2) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    const detectionScores: Record<string, number> = {};

    // Percent encoding detection
    const percentEncodedSegments = input.match(/%[0-9A-Fa-f]{2}/g);
    const hasPercentEncodedParts =
      percentEncodedSegments && percentEncodedSegments.length > 0;

    if (hasPercentEncodedParts) {
      const encodedCharCount = percentEncodedSegments.length * 3;
      const encodedRatio = encodedCharCount / input.length;

      if (encodedRatio > 0.8) {
        detectionScores["percentEncoding"] = 0.9;
      } else {
        detectionScores["partialPercentEncoding"] = 0.75 + encodedRatio * 0.2;
        detectionScores["plainText"] = 0.5 + (1 - encodedRatio) * 0.4;
      }
    }

    // URL parameter encoding detection
    try {
      const url = new URL(input);
      if (url.search && url.search.length > 1) {
        let hasEncodedParams = false;

        for (const [_, value] of new URLSearchParams(url.search)) {
          if (/%[0-9A-Fa-f]{2}/.test(value)) {
            detectionScores["percentEncoding"] = Math.max(
              detectionScores["percentEncoding"] || 0,
              0.85
            );
            hasEncodedParams = true;
          }
          if (/^[A-Za-z0-9+\/=]{4,}$/.test(value)) {
            detectionScores["base64"] = Math.max(
              detectionScores["base64"] || 0,
              0.82
            );
            hasEncodedParams = true;
          }
          if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
            detectionScores["rawHexadecimal"] = Math.max(
              detectionScores["rawHexadecimal"] || 0,
              0.8
            );
            hasEncodedParams = true;
          }
          if (/\\u[0-9A-Fa-f]{4}/.test(value)) {
            detectionScores["unicode"] = Math.max(
              detectionScores["unicode"] || 0,
              0.85
            );
            hasEncodedParams = true;
          }
          if (/\\x[0-9A-Fa-f]{2}/.test(value)) {
            detectionScores["jsEscape"] = Math.max(
              detectionScores["jsEscape"] || 0,
              0.83
            );
            hasEncodedParams = true;
          }
        }

        if (hasEncodedParams) {
          detectionScores["url"] = 0.9;
        }
      }
    } catch (e) {
      // Not a valid URL
    }

    // Standard encoding detection checks
    const detectionChecks: {
      type: ENC_TYPE;
      fn: (s: string) => boolean;
      score: number;
      minLength?: number;
      partialDetectionFn?: (s: string) => { isPartial: boolean; ratio: number };
    }[] = [
      { type: "doublepercent", fn: utils.isDoublePercent, score: 0.95 },
      {
        type: "percentEncoding",
        fn: utils.isPercentEncoding,
        score: 0.9,
        partialDetectionFn: (s: string) => {
          const matches = s.match(/%[0-9A-Fa-f]{2}/g);
          const isPartial = matches !== null && matches.length > 0;
          const ratio = isPartial ? (matches.length * 3) / s.length : 0;
          return { isPartial, ratio };
        },
      },
      {
        type: "base64",
        fn: utils.isBase64,
        score: 0.9,
        minLength: 4,
        partialDetectionFn: (s: string) => {
          const base64Segments = s.match(/[A-Za-z0-9+\/=]{4,}/g);
          const isPartial =
            base64Segments !== null &&
            base64Segments.some((seg) => seg.length >= 4);
          let totalBase64Length = 0;
          if (isPartial && base64Segments) {
            totalBase64Length = base64Segments.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalBase64Length / s.length };
        },
      },
      {
        type: "urlSafeBase64",
        fn: utils.isUrlSafeBase64,
        score: 0.93,
        minLength: 4,
      },
      {
        type: "base32",
        fn: utils.isBase32,
        score: 0.91,
        minLength: 8,
        partialDetectionFn: (s: string) => {
          const base32Pattern = /^[A-Z2-7]+=*$/;
          const isPureBase32 = base32Pattern.test(s);
          if (isPureBase32 && s.length >= 8) {
            return { isPartial: false, ratio: 1.0 };
          }
          return { isPartial: false, ratio: 0 };
        },
      },
      { type: "asciihex", fn: utils.isAsciiHex, score: 0.85 },
      { type: "asciioct", fn: utils.isAsciiOct, score: 0.85 },
      {
        type: "hex",
        fn: utils.isHex,
        score: 0.8,
        minLength: 6,
        partialDetectionFn: (s: string) => {
          const hexSegments = s.match(/[0-9A-Fa-f]{6,}/g);
          const isPartial = hexSegments !== null && hexSegments.length > 0;
          let totalHexLength = 0;
          if (isPartial && hexSegments) {
            totalHexLength = hexSegments.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalHexLength / s.length };
        },
      },
      {
        type: "rawHexadecimal",
        fn: utils.hasRawHexString,
        score: 0.85,
        minLength: 4,
        partialDetectionFn: (s: string) => {
          const isPureHex = /^[0-9A-Fa-f]+$/.test(s);
          const isEvenLength = s.length % 2 === 0;
          if (isPureHex && isEvenLength && s.length >= 6) {
            return { isPartial: false, ratio: 1.0 };
          }
          const hexSegments = s.match(/[0-9A-Fa-f]{6,}/g);
          const isPartial = hexSegments !== null && hexSegments.length > 0;
          let totalHexLength = 0;
          if (isPartial && hexSegments) {
            totalHexLength = hexSegments.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalHexLength / s.length };
        },
      },
      {
        type: "unicode",
        fn: utils.isUnicode,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const unicodeMatches = s.match(/\\u[0-9A-Fa-f]{4}/g);
          const isPartial = unicodeMatches !== null && unicodeMatches.length > 0;
          let totalUnicodeLength = 0;
          if (isPartial && unicodeMatches) {
            totalUnicodeLength = unicodeMatches.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalUnicodeLength / s.length };
        },
      },
      {
        type: "htmlEntity",
        fn: utils.isHtmlEntity,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const entityMatches = s.match(
            /&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/g
          );
          const isPartial = entityMatches !== null && entityMatches.length > 0;
          let totalEntityLength = 0;
          if (isPartial && entityMatches) {
            totalEntityLength = entityMatches.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalEntityLength / s.length };
        },
      },
      { type: "decimalHtmlEntity", fn: utils.isDecimalHtmlEntity, score: 0.83 },
      { type: "quotedPrintable", fn: utils.isQuotedPrintable, score: 0.77 },
      { type: "punycode", fn: utils.isPunycode, score: 0.9 },
      {
        type: "rot13",
        fn: utils.isRot13.bind(utils),
        score: 0.75,
        partialDetectionFn: (s: string) => {
          const hasOnlyLetters = /^[a-zA-Z]+$/.test(s);
          if (hasOnlyLetters && s.length >= 4) {
            try {
              const decoded = s.replace(/[a-zA-Z]/g, (c) => {
                const code = c.charCodeAt(0);
                const base = c <= "Z" ? 65 : 97;
                return String.fromCharCode(((code - base + 13) % 26) + base);
              });
              const commonWords =
                /\b(the|and|for|are|but|not|you|all|can|her|was|one|our|out|day)\b/i;
              if (commonWords.test(decoded)) {
                return { isPartial: false, ratio: 0.9 };
              }
            } catch {}
          }
          return { isPartial: false, ratio: 0 };
        },
      },
      { type: "utf7", fn: utils.isUtf7, score: 0.75 },
      {
        type: "jsEscape",
        fn: utils.isJsEscape,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const jsEscapeMatches = s.match(
            /\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g
          );
          const isPartial =
            jsEscapeMatches !== null && jsEscapeMatches.length > 0;
          let totalEscapeLength = 0;
          if (isPartial && jsEscapeMatches) {
            totalEscapeLength = jsEscapeMatches.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalEscapeLength / s.length };
        },
      },
      { type: "cssEscape", fn: utils.isCssEscape, score: 0.78 },
      { type: "jwt", fn: utils.hasJWTFormat, score: 0.95, minLength: 15 },
    ];

    for (const { type, fn, score, minLength, partialDetectionFn } of detectionChecks) {
      if (minLength && input.length < minLength) continue;

      try {
        if (fn(input)) {
          detectionScores[type] = score;
        } else if (partialDetectionFn) {
          const partialResult = partialDetectionFn(input);

          if (partialResult.ratio >= 0.95 && !partialResult.isPartial) {
            detectionScores[type] = score + 0.1;
          } else if (partialResult.isPartial || partialResult.ratio > 0) {
            const partialConfidence = 0.6 + partialResult.ratio * 0.3;
            detectionScores[
              `partial${type.charAt(0).toUpperCase() + type.slice(1)}`
            ] = partialConfidence;
          }
        }
      } catch (e) {
        // Skip failed checks
      }
    }

    // Find most likely encoding
    const types = Object.keys(detectionScores);
    if (types.length === 0) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    let mostLikely: ENC_TYPE | "plainText" | "mixedEncoding" = types[0] as ENC_TYPE | "plainText" | "mixedEncoding";
    let highestScore = detectionScores[types[0]];

    for (const type of types) {
      if (detectionScores[type] > highestScore) {
        highestScore = detectionScores[type];
        mostLikely = type as ENC_TYPE | "plainText" | "mixedEncoding";
      }
    }

    return {
      types,
      mostLikely,
      confidence: highestScore,
    };
  }
}
