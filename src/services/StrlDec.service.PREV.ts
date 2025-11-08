/**
 * String Decoder Service (Ultra-Slim Version)
 * Main orchestrator - delegates everything to specialized modules
 * 
 * Target: ~300 lines (down from 2,344!)
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
import { NehonixSharedUtils } from "../common/StrlCommonUtils";
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
import { EncodingDetector } from "./decoder/core/EncodingDetector.v2";

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
  // DETECTION METHODS (delegate to EncodingDetector)
  // ============================================================================

  static detectMixedEncodings(input: string): string[] {
    return EncodingDetector.detectMixedEncodings(input);
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
    return EncodingDetector.detectEncoding(input, depth, NehonixSharedUtils);
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
      if (
        secondDetection.mostLikely !== "plainText" &&
        secondDetection.confidence > 0.7
      ) {
        const nestedResult = this.detectNestedEncoding(decoded, depth + 1);
        return {
          isNested: true,
          nestedTypes: [
            initialDetection.mostLikely,
            ...(nestedResult.nestedTypes || [secondDetection.mostLikely]),
          ],
          confidenceScore:
            (initialDetection.confidence + secondDetection.confidence) / 2,
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
    const hexUrlResult = this.detectAndHandleRawHexUrl(input);
    if (hexUrlResult !== input) {
      return hexUrlResult;
    }

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
      if (encodingType === "any") {
        return this.decodeAnyToPlaintext(input, {
          maxIterations: 5,
        }).val();
      }

      if (input.includes("://") && input.includes("?")) {
        if (encodingType === "url" || encodingType === "percentEncoding") {
          const preprocessed = this.decodeUrlParameters(input);
          if (preprocessed !== input) {
            return preprocessed;
          }
        }
      }

      if (
        (input.includes("%") && /[A-Za-z0-9+/=]{4,}/.test(input)) ||
        (input.includes("\\x") && /[A-Za-z0-9+/=]{4,}/.test(input))
      ) {
        return this.decodeMixedContent(input);
      }

      // Delegate to appropriate decoder
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
