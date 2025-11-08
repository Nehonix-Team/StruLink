/**
 * Decoder Core Module
 * Main orchestration logic for decoding operations
 * 
 * Handles:
 * - Main decode method
 * - Smart decode (auto-detection)
 * - Single decode (recursive)
 * - Any-to-plaintext (iterative)
 */

import { ENC_TYPE, DEC_FEATURE_TYPE, UriHandlerInterface } from "../../../types";
import { NehonixSharedUtils } from "../../../common/StrlCommonUtils";
import { AppLogger } from "../../../common/AppLogger";
import { EncodingDetector } from "./EncodingDetector.v2";
import { PartialDecoder } from "./PartialDecoder";
import { UrlParameterDecoder } from "../url/UrlParameterDecoder";
import { UrlProcessor } from "../url/UrlProcessor";

// Import decoders
import {
  Base64Decoder,
  Base32Decoder,
  HexDecoder,
  PercentDecoder,
  UnicodeDecoder,
  HtmlDecoder,
  EscapeDecoder,
  SpecialDecoder,
} from "../decoders";

export class DecoderCore {
  private static throwError: boolean = true;

  /**
   * Decode any input to plaintext iteratively
   */
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
      const detection = EncodingDetector.detectEncoding(
        currentInput,
        iteration,
        NehonixSharedUtils
      );

      if (
        detection.mostLikely === "plainText" ||
        detection.confidence < confidenceThreshold
      ) {
        break;
      }

      try {
        const decoded = this.decode({
          input: currentInput,
          encodingType: detection.mostLikely as ENC_TYPE,
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

  /**
   * Smart decode with auto-detection
   */
  static smartDecode(input: string): string {
    // Check for raw hex URL
    const hexUrlResult = UrlProcessor.detectAndHandleRawHexUrl(input);
    if (hexUrlResult !== input) {
      return hexUrlResult;
    }

    // Auto-detect encoding
    const detection = EncodingDetector.detectEncoding(
      input,
      0,
      NehonixSharedUtils
    );

    // Handle mixed encodings
    if (
      detection.mostLikely === "mixedEncoding" ||
      detection.types.some((t) => t.startsWith("partial"))
    ) {
      return PartialDecoder.decodeMixed(input);
    }

    // Handle nested encodings
    const nestedDetection = this.detectNestedEncoding(input);
    if (nestedDetection.isNested) {
      return this.decodeAnyToPlaintext(input, {
        maxIterations: 5,
      }).val!();
    }

    return this.decode({
      input,
      encodingType: detection.mostLikely as ENC_TYPE,
    });
  }

  /**
   * Decode single encoding recursively
   */
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

      const detection = EncodingDetector.detectEncoding(
        decoded,
        0,
        NehonixSharedUtils
      );
      if (detection.mostLikely !== "plainText" && detection.confidence > 0.7) {
        return this.decodeSingle(decoded, detection.mostLikely as ENC_TYPE, depth + 1);
      }

      return decoded;
    } catch (e) {
      AppLogger.warn(`Decoding error in decodeSingle:`, e);
      return input;
    }
  }

  /**
   * Detect nested encodings
   */
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

    const initialDetection = EncodingDetector.detectEncoding(
      input,
      depth,
      NehonixSharedUtils
    );
    if (initialDetection.mostLikely === "plainText") {
      return { isNested: false };
    }

    try {
      const decoded = this.decode({
        input,
        encodingType: initialDetection.mostLikely as ENC_TYPE,
      });

      if (decoded === input) {
        return { isNested: false };
      }

      const secondDetection = EncodingDetector.detectEncoding(
        decoded,
        depth + 1,
        NehonixSharedUtils
      );
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

  /**
   * Main decode method - delegates to appropriate decoder
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
      // Special case: "any" encoding
      if (encodingType === "any") {
        return this.decodeAnyToPlaintext(input, {
          maxIterations: 5,
        }).val!();
      }

      // Special case: URLs with parameters
      if (input.includes("://") && input.includes("?")) {
        if (encodingType === "url" || encodingType === "percentEncoding") {
          const preprocessed = UrlParameterDecoder.decodeUrlParameters(input);
          if (preprocessed !== input) {
            return preprocessed;
          }
        }
      }

      // Special case: Mixed encoding
      if (
        (input.includes("%") && /[A-Za-z0-9+/=]{4,}/.test(input)) ||
        (input.includes("\\x") && /[A-Za-z0-9+/=]{4,}/.test(input))
      ) {
        return PartialDecoder.decodeMixedContent(input);
      }

      // Delegate to appropriate decoder
      return this.delegateDecode(input, encodingType);
    } catch (e) {
      if (opt.throwError) {
        throw e;
      } else {
        AppLogger.error("Decode error:", e);
        return input;
      }
    }
  }

  /**
   * Delegate to the appropriate decoder based on encoding type
   */
  private static delegateDecode(
    input: string,
    encodingType: ENC_TYPE | DEC_FEATURE_TYPE
  ): string {
    switch (encodingType) {
      case "percentEncoding":
      case "url":
        return PercentDecoder.decodePercentEncoding(input);
      case "doublepercent":
        return PercentDecoder.decodeDoublePercentEncoding(input);
      case "base64":
        return NehonixSharedUtils.decodeB64(input);
      case "urlSafeBase64":
        return Base64Decoder.decodeUrlSafeBase64(input);
      case "base32":
        return Base32Decoder.decodeBase32(input);
      case "hex":
        return HexDecoder.decodeHex(input);
      case "unicode":
        return UnicodeDecoder.decodeUnicode(input);
      case "htmlEntity":
        return HtmlDecoder.decodeHTMLEntities(input);
      case "decimalHtmlEntity":
        return HtmlDecoder.decodeDecimalHtmlEntity(input);
      case "punycode":
        return SpecialDecoder.decodePunycode(input);
      case "rot13":
        return SpecialDecoder.decodeRot13(input);
      case "asciihex":
        return HexDecoder.decodeAsciiHex(input);
      case "asciioct":
        return HexDecoder.decodeAsciiOct(input);
      case "jsEscape":
        return EscapeDecoder.decodeJsEscape(input);
      case "cssEscape":
        return EscapeDecoder.decodeCssEscape(input);
      case "utf7":
        return UnicodeDecoder.decodeUtf7(input);
      case "quotedPrintable":
        return EscapeDecoder.decodeQuotedPrintable(input);
      case "jwt":
        return SpecialDecoder.decodeJWT(input);
      case "rawHexadecimal":
        return HexDecoder.decodeRawHex(input);
      default:
        throw new Error(`Unsupported encoding type: ${encodingType}`);
    }
  }
}
