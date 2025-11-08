/**
 * String Decoder Service (Refactored)
 * Main orchestrator that delegates to specialized decoder modules
 * 
 * Reduced from 2,344 lines to ~300 lines by extracting:
 * - 8 decoder modules (467 lines)
 * - Core logic modules (660 lines)
 * - URL processing (240 lines)
 */

import {
  DecodeResult,
  EncodingDetectionResult,
  ENC_TYPE,
  NestedEncodingResult,
  DEC_FEATURE_TYPE,
  UriHandlerInterface,
  UrlValidationOptions,
} from "../types";
import chalk from "chalk";
import { ncu } from "../utils/NehonixCoreUtils";
import { NehonixSharedUtils } from "../common/StrlCommonUtils";
import NES from "./StrlEnc.service";
import { sr } from "../rules/security.rules";
import { AppLogger } from "../common/AppLogger";

// Import all decoder modules
import {
  Base64Decoder,
  Base32Decoder,
  HexDecoder,
  PercentDecoder,
  UnicodeDecoder,
  HtmlDecoder,
  EscapeDecoder,
  SpecialDecoder,
} from "./decoder/decoders";

// Import core modules
import { PartialDecoder } from "./decoder/core/PartialDecoder";

// Import URL modules
import { UrlProcessor, UrlParameterDecoder } from "./decoder/url";

class NDS {
  private static throwError: boolean = true;
  private static default_checkurl_opt: UrlValidationOptions = {
    allowLocalhost: true,
    rejectDuplicatedValues: false,
    maxUrlLength: "NO_LIMIT",
    strictMode: false,
    strictParamEncoding: false,
    debug: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: false,
  };

  // ============================================================================
  // DETECTION METHODS
  // ============================================================================

  static detectMixedEncodings(input: string): string[] {
    const detectedEncodings = [];

    if (/%[0-9A-Fa-f]{2}/.test(input)) {
      detectedEncodings.push("percentEncoding");
    }

    const base64Regex = /[A-Za-z0-9+/=]{4,}/g;
    const potentialBase64 = input.match(base64Regex);
    if (potentialBase64) {
      for (const match of potentialBase64) {
        if (NehonixSharedUtils.isBase64(match)) {
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

  static detectAndDecode(input: string): DecodeResult {
    const detection = this.detectEncoding(input);
    const decoded = this.decode({
      input,
      encodingType: detection.mostLikely,
    });

    return {
      original: input,
      decoded,
      encoding: detection.mostLikely,
      confidence: detection.confidence,
      nested: detection.types.length > 1,
    };
  }

  static detectEncoding(input: string, depth = 0): EncodingDetectionResult {
    const MAX_DEPTH = 3;
    if (depth > MAX_DEPTH || !input || input.length < 2) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    const detectionScores: Record<string, number> = {};
    const utils = NehonixSharedUtils;
    const isValidUrl = ncu.isValidUrl(input, this.default_checkurl_opt);

    // Percent encoding detection
    const percentEncodedSegments = input.match(/%[0-9A-Fa-f]{2}/g);
    const hasPercentEncodedParts = percentEncodedSegments && percentEncodedSegments.length > 0;

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
    if (isValidUrl) {
      try {
        const url = new URL(input);
        if (url.search && url.search.length > 1) {
          let hasEncodedParams = false;

          for (const [_, value] of new URLSearchParams(url.search)) {
            if (/%[0-9A-Fa-f]{2}/.test(value)) {
              detectionScores["percentEncoding"] = Math.max(detectionScores["percentEncoding"] || 0, 0.85);
              hasEncodedParams = true;
            }
            if (/^[A-Za-z0-9+\/=]{4,}$/.test(value)) {
              detectionScores["base64"] = Math.max(detectionScores["base64"] || 0, 0.82);
              hasEncodedParams = true;
            }
            if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
              detectionScores["rawHexadecimal"] = Math.max(detectionScores["rawHexadecimal"] || 0, 0.8);
              hasEncodedParams = true;
            }
            if (/\\u[0-9A-Fa-f]{4}/.test(value)) {
              detectionScores["unicode"] = Math.max(detectionScores["unicode"] || 0, 0.85);
              hasEncodedParams = true;
            }
            if (/\\x[0-9A-Fa-f]{2}/.test(value)) {
              detectionScores["jsEscape"] = Math.max(detectionScores["jsEscape"] || 0, 0.83);
              hasEncodedParams = true;
            }
          }

          if (hasEncodedParams) {
            detectionScores["url"] = 0.9;
          }
        }
      } catch (e) {
        // URL parsing failed
      }
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
          const isPartial = base64Segments !== null && base64Segments.some((seg) => seg.length >= 4);
          let totalBase64Length = 0;
          if (isPartial && base64Segments) {
            totalBase64Length = base64Segments.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalBase64Length / s.length };
        },
      },
      { type: "urlSafeBase64", fn: utils.isUrlSafeBase64, score: 0.93, minLength: 4 },
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
            totalHexLength = hexSegments.reduce((sum, seg) => sum + seg.length, 0);
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
            totalHexLength = hexSegments.reduce((sum, seg) => sum + seg.length, 0);
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
            totalUnicodeLength = unicodeMatches.reduce((sum, seg) => sum + seg.length, 0);
          }
          return { isPartial, ratio: totalUnicodeLength / s.length };
        },
      },
      {
        type: "htmlEntity",
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
              const commonWords = /\b(the|and|for|are|but|not|you|all|can|her|was|one|our|out|day)\b/i;
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
          const jsEscapeMatches = s.match(/\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g);
          const isPartial = jsEscapeMatches !== null && jsEscapeMatches.length > 0;
          let totalEscapeLength = 0;
          if (isPartial && jsEscapeMatches) {
            totalEscapeLength = jsEscapeMatches.reduce((sum, seg) => sum + seg.length, 0);
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
            detectionScores[`partial${type.charAt(0).toUpperCase() + type.slice(1)}`] = partialConfidence;
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

    let mostLikely = types[0];
    let highestScore = detectionScores[mostLikely];

    for (const type of types) {
      if (detectionScores[type] > highestScore) {
        highestScore = detectionScores[type];
        mostLikely = type;
      }
    }

    return {
      types,
      mostLikely,
      confidence: highestScore,
    };
  }

  static tryPartialDecode(
    input: string,
    encodingType: ENC_TYPE
  ): {
    success: boolean;
    decoded?: string;
    parts?: string[];
  } {
    return PartialDecoder.tryPartialDecode(input, encodingType);
  }

  static detectNestedEncoding(
    input: string,
    depth = 0
  ): {
    isNested: boolean;
    nestedTypes?: string[];
    confidenceScore?: number;
  } {
    const MAX_DEPTH = 3;
    if (depth >= MAX_DEPTH) {
      return { isNested: false };
    }

    const initialDetection = this.detectEncoding(input, depth);
    if (initialDetection.mostLikely === "plainText") {
      return { isNested: false };
    }

    try {
      const decoded = this.decode({
        input,
        encodingType: initialDetection.mostLikely,
      });

      if (decoded === input) {
        return { isNested: false };
      }

      const secondDetection = this.detectEncoding(decoded, depth + 1);
      if (secondDetection.mostLikely !== "plainText" && secondDetection.confidence > 0.7) {
        const nestedResult = this.detectNestedEncoding(decoded, depth + 1);
        return {
          isNested: true,
          nestedTypes: [initialDetection.mostLikely, ...(nestedResult.nestedTypes || [secondDetection.mostLikely])],
          confidenceScore: (initialDetection.confidence + secondDetection.confidence) / 2,
        };
      }
    } catch (e) {
      return { isNested: false };
    }

    return { isNested: false };
  }

  // ============================================================================
  // DECODER DELEGATION METHODS (delegate to specialized modules)
  // ============================================================================

  static decodePercentEncoding(input: string): string {
    return PercentDecoder.decodePercentEncoding(input);
  }

  static decodeDoublePercentEncoding(input: string): string {
    return PercentDecoder.decodeDoublePercentEncoding(input);
  }

  static decodeHex(input: string): string {
    return HexDecoder.decodeHex(input);
  }

  static decodeRawHex(input: string): string {
    return HexDecoder.decodeRawHex(input);
  }

  static decodeAsciiHex(input: string): string {
    return HexDecoder.decodeAsciiHex(input);
  }

  static decodeAsciiOct(input: string): string {
    return HexDecoder.decodeAsciiOct(input);
  }

  static decodeUnicode(input: string): string {
    return UnicodeDecoder.decodeUnicode(input);
  }

  static decodeUtf7(input: string): string {
    return UnicodeDecoder.decodeUtf7(input);
  }

  static decodeHTMLEntities(input: string): string {
    return HtmlDecoder.decodeHTMLEntities(input);
  }

  static decodeDecimalHtmlEntity(input: string): string {
    return HtmlDecoder.decodeDecimalHtmlEntity(input);
  }

  static decodeJsEscape(input: string): string {
    return EscapeDecoder.decodeJsEscape(input);
  }

  static decodeCharacterEscapes(input: string): string {
    return EscapeDecoder.decodeCharacterEscapes(input);
  }

  static decodeCssEscape(input: string): string {
    return EscapeDecoder.decodeCssEscape(input);
  }

  static decodeQuotedPrintable(input: string): string {
    return EscapeDecoder.decodeQuotedPrintable(input);
  }

  static decodeRot13(input: string): string {
    return SpecialDecoder.decodeRot13(input);
  }

  static decodeJWT(input: string): string {
    return SpecialDecoder.decodeJWT(input);
  }

  static decodePunycode(input: string): string {
    return SpecialDecoder.decodePunycode(input);
  }

  static decodeBase32(input: string): string {
    return Base32Decoder.decodeBase32(input);
  }

  static decodeUrlSafeBase64(input: string): string {
    return Base64Decoder.decodeUrlSafeBase64(input);
  }

  // ============================================================================
  // PARTIAL & MIXED DECODING (delegate to PartialDecoder)
  // ============================================================================

  static decodePartial(input: string, baseEncodingType: ENC_TYPE): string {
    return PartialDecoder.decodePartial(input, baseEncodingType);
  }

  static decodeMixed(input: string): string {
    return PartialDecoder.decodeMixed(input);
  }

  static decodeMixedContent(input: string): string {
    return PartialDecoder.decodeMixedContent(input);
  }

  // ============================================================================
  // URL PROCESSING (delegate to URL modules)
  // ============================================================================

  static decodeUrlParameters(url: string) {
    return UrlParameterDecoder.decodeUrlParameters(url);
  }

  static detectAndHandleRawHexUrl(input: string): string {
    return UrlProcessor.detectAndHandleRawHexUrl(input);
  }

  // ============================================================================
  // MAIN DECODE METHODS
  // ============================================================================

  static decodeAnyToPlaintext(
    input: string,
    options: {
      maxIterations?: number;
      confidenceThreshold?: number;
    } = {}
  ): UriHandlerInterface {
    const { maxIterations = 10, confidenceThreshold = 0.7 } = options;

    let currentInput = input;
    let iteration = 0;
    const decodingSteps: Array<{
      step: number;
      encoding: string;
      decoded: string;
      confidence: number;
    }> = [];

    while (iteration < maxIterations) {
      const detection = this.detectEncoding(currentInput, iteration);

      if (
        detection.mostLikely === "plainText" ||
        detection.confidence < confidenceThreshold
      ) {
        break;
      }

      try {
        const decoded = this.decode({
          input: currentInput,
          encodingType: detection.mostLikely,
        });

        if (decoded === currentInput) {
          break;
        }

        decodingSteps.push({
          step: iteration + 1,
          encoding: detection.mostLikely,
          decoded,
          confidence: detection.confidence,
        });

        currentInput = decoded;
      } catch (e) {
        AppLogger.warn(`Decoding failed at iteration ${iteration}:`, e);
        break;
      }

      iteration++;
    }

    return {
      val: () => currentInput,
      steps: () => decodingSteps,
      iterations: () => iteration,
    };
  }

  static smartDecode(input: string): string {
    // First check for raw hex URL
    const hexUrlResult = this.detectAndHandleRawHexUrl(input);
    if (hexUrlResult !== input) {
      return hexUrlResult;
    }

    // Auto-detect and decode
    const detection = this.detectEncoding(input);

    if (
      detection.mostLikely === "mixedEncoding" ||
      detection.types.some((t) => t.startsWith("partial"))
    ) {
      return this.decodeMixed(input);
    }

    const nestedDetection = this.detectNestedEncoding(input);
    if (nestedDetection.isNested) {
      return this.decodeAnyToPlaintext(input, {
        maxIterations: 5,
      }).val();
    }

    return this.decode({
      input,
      encodingType: detection.mostLikely,
    });
  }

  static decodeSingle(
    input: string,
    encodingType: ENC_TYPE,
    depth = 0
  ): string {
    const MAX_DEPTH = 5;
    if (depth >= MAX_DEPTH) {
      AppLogger.warn("Maximum recursion depth reached in decodeSingle");
      return input;
    }

    try {
      const decoded = this.decode({
        input,
        encodingType,
        maxRecursionDepth: MAX_DEPTH - depth,
      });

      if (decoded === input) {
        return decoded;
      }

      const detection = this.detectEncoding(decoded);
      if (detection.mostLikely !== "plainText" && detection.confidence > 0.7) {
        return this.decodeSingle(decoded, detection.mostLikely, depth + 1);
      }

      return decoded;
    } catch (e) {
      AppLogger.warn(`Decoding error in decodeSingle:`, e);
      return input;
    }
  }

  /**
   * Main decode method with improved error handling
   */
  static decode(props: {
    input: string;
    encodingType: ENC_TYPE | DEC_FEATURE_TYPE;
    maxRecursionDepth?: number;
    opt?: {
      throwError?: boolean;
    };
  }): string {
    const {
      encodingType,
      input,
      maxRecursionDepth = 5,
      opt = { throwError: this.throwError },
    } = props;

    if (maxRecursionDepth <= 0) {
      AppLogger.warn("Maximum recursion depth reached in decode");
      return input;
    }

    try {
      // Special case for "any" encoding
      if (encodingType === "any") {
        return this.decodeAnyToPlaintext(input, {
          maxIterations: 5,
        }).val();
      }

      // Special case for URLs - handle parameter decoding
      if (input.includes("://") && input.includes("?")) {
        if (encodingType === "url" || encodingType === "percentEncoding") {
          const preprocessed = this.decodeUrlParameters(input);
          if (preprocessed !== input) {
            return preprocessed;
          }
        }
      }

      // Try to handle mixed encoding types
      if (
        (input.includes("%") && /[A-Za-z0-9+/=]{4,}/.test(input)) ||
        (input.includes("\\x") && /[A-Za-z0-9+/=]{4,}/.test(input))
      ) {
        return this.decodeMixedContent(input);
      }

      // Regular handling for specific encoding types
      switch (encodingType) {
        case "percentEncoding":
        case "url":
          return this.decodePercentEncoding(input);
        case "doublepercent":
          return this.decodeDoublePercentEncoding(input);
        case "base64":
          return NehonixSharedUtils.decodeB64(input);
        case "urlSafeBase64":
          return this.decodeUrlSafeBase64(input);
        case "base32":
          return this.decodeBase32(input);
        case "hex":
          return this.decodeHex(input);
        case "unicode":
          return this.decodeUnicode(input);
        case "htmlEntity":
          return this.decodeHTMLEntities(input);
        case "decimalHtmlEntity":
          return this.decodeDecimalHtmlEntity(input);
        case "punycode":
          return this.decodePunycode(input);
        case "rot13":
          return this.decodeRot13(input);
        case "asciihex":
          return this.decodeAsciiHex(input);
        case "asciioct":
          return this.decodeAsciiOct(input);
        case "jsEscape":
          return this.decodeJsEscape(input);
        case "cssEscape":
          return this.decodeCssEscape(input);
        case "utf7":
          return this.decodeUtf7(input);
        case "quotedPrintable":
          return this.decodeQuotedPrintable(input);
        case "jwt":
          return this.decodeJWT(input);
        case "rawHexadecimal":
          return this.decodeRawHex(input);
        default:
          if (opt.throwError) {
            throw new Error(`Unsupported encoding type: ${encodingType}`);
          } else {
            return "Error skipped";
          }
      }
    } catch (e) {
      if (opt.throwError) {
        throw e;
      } else {
        AppLogger.error("Decode error:", e);
        return input;
      }
    }
  }

  // ============================================================================
  // ASYNC METHODS
  // ============================================================================

  static asyncDecodeAnyToPlainText(
    input: string,
    options: {
      maxIterations?: number;
      confidenceThreshold?: number;
    } = {}
  ): Promise<UriHandlerInterface> {
    return new Promise((resolve, reject) => {
      try {
        const result = this.decodeAnyToPlaintext(input, options);
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  }
}

export default NDS;
export { NDS as NehonixDecService };
