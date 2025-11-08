/**
 * String Decoder Service (FINAL - Ultra-Minimal)
 * Pure delegation layer - all logic extracted to modules
 * 
 * Target: ~200 lines (down from 2,344!)
 */

import {
  DecodeResult,
  EncodingDetectionResult,
  ENC_TYPE,
  DEC_FEATURE_TYPE,
  UriHandlerInterface,
} from "../types";
import { NehonixSharedUtils } from "../common/StrlCommonUtils";

// Import all specialized modules
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

import { PartialDecoder } from "./decoder/core/PartialDecoder";
import { EncodingDetector } from "./decoder/core/EncodingDetector.v2";
import { DecoderCore } from "./decoder/core/DecoderCore";
import { UrlProcessor, UrlParameterDecoder } from "./decoder/url";

class NDS {
  // ============================================================================
  // DETECTION METHODS - Delegate to EncodingDetector
  // ============================================================================

  static detectMixedEncodings(input: string): string[] {
    return EncodingDetector.detectMixedEncodings(input);
  }

  static detectAndDecode(input: string): DecodeResult {
    const detection = this.detectEncoding(input);
    const decoded = this.decode({
      input,
      encodingType: detection.mostLikely as ENC_TYPE,
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

  static detectNestedEncoding(
    input: string,
    depth = 0
  ): {
    isNested: boolean;
    nestedTypes?: string[];
    confidenceScore?: number;
  } {
    return DecoderCore.detectNestedEncoding(input, depth);
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

  // ============================================================================
  // DECODER METHODS - Delegate to specialized decoders
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
  // PARTIAL & MIXED DECODING - Delegate to PartialDecoder
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
  // URL PROCESSING - Delegate to URL modules
  // ============================================================================

  static decodeUrlParameters(url: string) {
    return UrlParameterDecoder.decodeUrlParameters(url);
  }

  static detectAndHandleRawHexUrl(input: string): string {
    return UrlProcessor.detectAndHandleRawHexUrl(input);
  }

  // ============================================================================
  // MAIN DECODE METHODS - Delegate to DecoderCore
  // ============================================================================

  static decodeAnyToPlaintext(
    input: string,
    options: {
      maxIterations?: number;
      confidenceThreshold?: number;
    } = {}
  ): UriHandlerInterface {
    return DecoderCore.decodeAnyToPlaintext(input, options);
  }

  static smartDecode(input: string): string {
    return DecoderCore.smartDecode(input);
  }

  static decodeSingle(
    input: string,
    encodingType: ENC_TYPE,
    depth = 0
  ): string {
    return DecoderCore.decodeSingle(input, encodingType, depth);
  }

  static decode(props: {
    input: string;
    encodingType: ENC_TYPE | DEC_FEATURE_TYPE;
    maxRecursionDepth?: number;
    opt?: {
      throwError?: boolean;
    };
  }): string {
    return DecoderCore.decode(props);
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
