/**
 * Encoding Detection Module
 * Handles automatic detection of encoding types with confidence scoring
 * 
 * This is a critical module extracted from StrlDec.service.ts
 * Contains ~460 lines of detection logic
 */

import { EncodingDetectionResult, ENC_TYPE } from "../../../types";
// Note: Avoiding circular dependencies by importing only what's needed
// Full integration with NehonixSharedUtils and ncu will be done when
// we refactor the main StrlDec.service to use this module

export class EncodingDetector {
  private static readonly MAX_DEPTH = 3;
  private static readonly default_checkurl_opt = {
    allowLocalhost: true,
    rejectDuplicatedValues: false,
    maxUrlLength: "NO_LIMIT" as const,
    strictMode: false,
    strictParamEncoding: false,
    debug: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: false,
  };

  /**
   * Detects the encoding type of an input string
   * Returns the most likely encoding with confidence score
   * 
   * @param input - String to analyze
   * @param depth - Recursion depth for nested encoding detection
   * @returns Detection result with types, most likely type, and confidence
   */
  static detectEncoding(input: string, depth = 0): EncodingDetectionResult {
    if (depth > this.MAX_DEPTH || !input || input.length < 2) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    const detectionScores: Record<string, number> = {};
    const utils = NehonixSharedUtils;
    const isValidUrl = ncu.isValidUrl(input, this.default_checkurl_opt);

    // Check for percent encoding patterns
    this.detectPercentEncoding(input, detectionScores);

    // Special handling for URLs
    if (isValidUrl) {
      this.detectUrlEncodings(input, detectionScores);
    }

    // Standard encoding detection checks
    this.runStandardDetectionChecks(input, detectionScores, utils);

    // Determine the most likely encoding
    return this.calculateMostLikely(detectionScores);
  }

  /**
   * Detects percent encoding patterns
   */
  private static detectPercentEncoding(
    input: string,
    scores: Record<string, number>
  ): void {
    const percentEncodedSegments = input.match(/%[0-9A-Fa-f]{2}/g);
    const hasPercentEncodedParts =
      percentEncodedSegments && percentEncodedSegments.length > 0;

    if (hasPercentEncodedParts) {
      const encodedCharCount = percentEncodedSegments.length * 3;
      const encodedRatio = encodedCharCount / input.length;

      if (encodedRatio > 0.8) {
        scores["percentEncoding"] = 0.9;
      } else {
        scores["partialPercentEncoding"] = 0.75 + encodedRatio * 0.2;
        scores["plainText"] = 0.5 + (1 - encodedRatio) * 0.4;
      }
    }
  }

  /**
   * Detects encodings in URL parameters
   */
  private static detectUrlEncodings(
    input: string,
    scores: Record<string, number>
  ): void {
    try {
      const url = new URL(input);
      if (url.search && url.search.length > 1) {
        let hasEncodedParams = false;

        for (const [_, value] of new URLSearchParams(url.search)) {
          if (/%[0-9A-Fa-f]{2}/.test(value)) {
            scores["percentEncoding"] = Math.max(scores["percentEncoding"] || 0, 0.85);
            hasEncodedParams = true;
          }
          if (/^[A-Za-z0-9+\/=]{4,}$/.test(value)) {
            scores["base64"] = Math.max(scores["base64"] || 0, 0.82);
            hasEncodedParams = true;
          }
          if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
            scores["rawHexadecimal"] = Math.max(scores["rawHexadecimal"] || 0, 0.8);
            hasEncodedParams = true;
          }
          if (/\\u[0-9A-Fa-f]{4}/.test(value)) {
            scores["unicode"] = Math.max(scores["unicode"] || 0, 0.85);
            hasEncodedParams = true;
          }
          if (/\\x[0-9A-Fa-f]{2}/.test(value)) {
            scores["jsEscape"] = Math.max(scores["jsEscape"] || 0, 0.83);
            hasEncodedParams = true;
          }
        }

        if (hasEncodedParams) {
          scores["url"] = 0.9;
        }
      }
    } catch (e) {
      // URL parsing failed, continue
    }
  }

  /**
   * Runs standard detection checks for all encoding types
   * This is the main detection logic - extracted to keep it modular
   */
  private static runStandardDetectionChecks(
    input: string,
    scores: Record<string, number>,
    utils: typeof NehonixSharedUtils
  ): void {
    // Detection configuration for each encoding type
    const detectionChecks = this.getDetectionChecks(utils);

    for (const { type, fn, score, minLength, partialDetectionFn } of detectionChecks) {
      // Skip if input too short
      if (minLength && input.length < minLength) continue;

      try {
        // Full detection
        if (fn(input)) {
          scores[type] = score;
          // Boost confidence if decoding succeeds
          this.verifyByDecoding(input, type, scores);
        }
        // Partial detection
        else if (partialDetectionFn) {
          this.handlePartialDetection(input, type, score, partialDetectionFn, scores);
        }
      } catch (e) {
        // Skip failed checks
      }
    }
  }

  /**
   * Get detection configuration for all encoding types
   * Separated for clarity and maintainability
   */
  private static getDetectionChecks(utils: typeof NehonixSharedUtils) {
    return [
      { type: "doublepercent" as ENC_TYPE, fn: utils.isDoublePercent, score: 0.95 },
      {
        type: "percentEncoding" as ENC_TYPE,
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
        type: "base64" as ENC_TYPE,
        fn: utils.isBase64,
        score: 0.9,
        minLength: 4,
        partialDetectionFn: (s: string) => {
          const base64Segments = s.match(/[A-Za-z0-9+\/=]{4,}/g);
          const isPartial = base64Segments !== null && base64Segments.some((seg) => seg.length >= 4);
          let totalBase64Length = 0;
          if (isPartial && base64Segments) {
            totalBase64Length = base64Segments.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalBase64Length / s.length };
        },
      },
      {
        type: "urlSafeBase64" as ENC_TYPE,
        fn: utils.isUrlSafeBase64,
        score: 0.93,
        minLength: 4,
      },
      {
        type: "base32" as ENC_TYPE,
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
      { type: "asciihex" as ENC_TYPE, fn: utils.isAsciiHex, score: 0.85 },
      { type: "asciioct" as ENC_TYPE, fn: utils.isAsciiOct, score: 0.85 },
      {
        type: "hex" as ENC_TYPE,
        fn: utils.isHex,
        score: 0.8,
        minLength: 6,
        partialDetectionFn: (s: string) => {
          const hexSegments = s.match(/[0-9A-Fa-f]{6,}/g);
          const isPartial = hexSegments !== null && hexSegments.length > 0;
          let totalHexLength = 0;
          if (isPartial && hexSegments) {
            totalHexLength = hexSegments.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalHexLength / s.length };
        },
      },
      {
        type: "rawHexadecimal" as ENC_TYPE,
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
            totalHexLength = hexSegments.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalHexLength / s.length };
        },
      },
      {
        type: "unicode" as ENC_TYPE,
        fn: utils.isUnicode,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const unicodeMatches = s.match(/\\u[0-9A-Fa-f]{4}/g);
          const isPartial = unicodeMatches !== null && unicodeMatches.length > 0;
          let totalUnicodeLength = 0;
          if (isPartial && unicodeMatches) {
            totalUnicodeLength = unicodeMatches.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalUnicodeLength / s.length };
        },
      },
      {
        type: "htmlEntity" as ENC_TYPE,
        fn: utils.isHtmlEntity,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const entityMatches = s.match(/&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/g);
          const isPartial = entityMatches !== null && entityMatches.length > 0;
          let totalEntityLength = 0;
          if (isPartial && entityMatches) {
            totalEntityLength = entityMatches.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalEntityLength / s.length };
        },
      },
      { type: "decimalHtmlEntity" as ENC_TYPE, fn: utils.isDecimalHtmlEntity, score: 0.83 },
      { type: "quotedPrintable" as ENC_TYPE, fn: utils.isQuotedPrintable, score: 0.77 },
      { type: "punycode" as ENC_TYPE, fn: utils.isPunycode, score: 0.9 },
      {
        type: "rot13" as ENC_TYPE,
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
              const commonWords = /\b(the|and|for|are|but|not|you|all|can|her|was|one|our|out|day)\b/i;
              if (commonWords.test(decoded)) {
                return { isPartial: false, ratio: 0.9 };
              }
            } catch {}
          }
          return { isPartial: false, ratio: 0 };
        },
      },
      { type: "utf7" as ENC_TYPE, fn: utils.isUtf7, score: 0.75 },
      {
        type: "jsEscape" as ENC_TYPE,
        fn: utils.isJsEscape,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const jsEscapeMatches = s.match(/\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g);
          const isPartial = jsEscapeMatches !== null && jsEscapeMatches.length > 0;
          let totalEscapeLength = 0;
          if (isPartial && jsEscapeMatches) {
            totalEscapeLength = jsEscapeMatches.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalEscapeLength / s.length };
        },
      },
      { type: "cssEscape" as ENC_TYPE, fn: utils.isCssEscape, score: 0.78 },
      { type: "jwt" as ENC_TYPE, fn: utils.hasJWTFormat, score: 0.95, minLength: 15 },
    ];
  }

  /**
   * Verify detection by attempting to decode
   */
  private static verifyByDecoding(
    input: string,
    type: string,
    scores: Record<string, number>
  ): void {
    // TODO: Implement verification by decoding
    // This would require importing decoders, which we'll do in the next phase
  }

  /**
   * Handle partial detection results
   */
  private static handlePartialDetection(
    input: string,
    type: string,
    score: number,
    partialDetectionFn: (s: string) => { isPartial: boolean; ratio: number },
    scores: Record<string, number>
  ): void {
    const partialResult = partialDetectionFn(input);

    if (partialResult.ratio >= 0.95 && !partialResult.isPartial) {
      scores[type] = score + 0.1;
    } else if (partialResult.isPartial || partialResult.ratio > 0) {
      const partialConfidence = 0.6 + partialResult.ratio * 0.3;
      scores[`partial${type.charAt(0).toUpperCase() + type.slice(1)}`] = partialConfidence;
    }
  }

  /**
   * Calculate the most likely encoding from scores
   */
  private static calculateMostLikely(
    scores: Record<string, number>
  ): EncodingDetectionResult {
    const types = Object.keys(scores);

    if (types.length === 0) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    // Find highest score
    let mostLikely = types[0];
    let highestScore = scores[mostLikely];

    for (const type of types) {
      if (scores[type] > highestScore) {
        highestScore = scores[type];
        mostLikely = type;
      }
    }

    return {
      types,
      mostLikely,
      confidence: highestScore,
    };
  }

  /**
   * Detects nested encodings
   * TODO: Implement in next phase
   */
  static detectNestedEncoding(
    input: string,
    depth = 0
  ): {
    isNested: boolean;
    nestedTypes?: string[];
    confidenceScore?: number;
  } {
    // Placeholder - will implement in next phase
    return { isNested: false };
  }
}
