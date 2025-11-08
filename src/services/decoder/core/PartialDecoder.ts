/**
 * Partial Decoding Module
 * Handles partial and mixed encoding decoding
 * 
 * Extracted from StrlDec.service.ts (~150 lines)
 */

import { ENC_TYPE } from "../../../types";
import { AppLogger } from "../../../common/AppLogger";
import {
  Base64Decoder,
  HexDecoder,
  PercentDecoder,
  UnicodeDecoder,
  EscapeDecoder,
} from "../decoders";
 
export class PartialDecoder {
  /**
   * Decodes a string with partial encoding
   * Only decodes the encoded segments, preserving plain text
   * 
   * @param input - String with partial encoding
   * @param baseEncodingType - The encoding type to decode
   * @returns Partially decoded string
   */
  static decodePartial(input: string, baseEncodingType: ENC_TYPE): string {
    try {
      switch (baseEncodingType) {
        case "percentEncoding":
          return this.decodePartialPercent(input);

        case "base64":
          return this.decodePartialBase64(input);

        case "urlSafeBase64":
          return this.decodePartialUrlSafeBase64(input);

        case "htmlEntity":
          return this.decodePartialHtmlEntity(input);

        case "unicode":
          return this.decodePartialUnicode(input);

        case "jsEscape":
          return this.decodePartialJsEscape(input);

        case "rawHexadecimal":
          return this.decodePartialRawHex(input);

        default:
          return input;
      }
    } catch (e) {
      AppLogger.warn(`Partial decode error (${baseEncodingType}):`, e);
      return input;
    }
  }

  /**
   * Decode only percent-encoded segments
   */
  private static decodePartialPercent(input: string): string {
    return input.replace(/%[0-9A-Fa-f]{2}/g, (match) => {
      try {
        return decodeURIComponent(match);
      } catch (e) {
        return match;
      }
    });
  }

  /**
   * Find and decode base64 segments
   */
  private static decodePartialBase64(input: string): string {
    return input.replace(/[A-Za-z0-9+\/=]{4,}/g, (match) => {
      try {
        if (/^[A-Za-z0-9+\/=]+$/.test(match) && match.length % 4 === 0) {
          const decoded = Base64Decoder.decodeBase64(match);
          // Verify if result is readable text (printable ASCII)
          const isPrintable = /^[\x20-\x7E]+$/.test(decoded);
          return isPrintable ? decoded : match;
        }
        return match;
      } catch (e) {
        return match;
      }
    });
  }

  /**
   * Find and decode URL-safe base64 segments
   */
  private static decodePartialUrlSafeBase64(input: string): string {
    return input.replace(/[A-Za-z0-9\-_=]{4,}/g, (match) => {
      try {
        if (/^[A-Za-z0-9\-_=]+$/.test(match)) {
          const decoded = Base64Decoder.decodeUrlSafeBase64(match);
          // Verify if result is readable text
          const isPrintable = /^[\x20-\x7E]+$/.test(decoded);
          return isPrintable ? decoded : match;
        }
        return match;
      } catch (e) {
        return match;
      }
    });
  }

  /**
   * Decode only HTML entity segments
   */
  private static decodePartialHtmlEntity(input: string): string {
    return input.replace(
      /&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/g,
      (match) => {
        try {
          // Simple entity decoding without DOM
          if (match.startsWith("&#x")) {
            const hex = match.slice(3, -1);
            return String.fromCharCode(parseInt(hex, 16));
          } else if (match.startsWith("&#")) {
            const dec = match.slice(2, -1);
            return String.fromCharCode(parseInt(dec, 10));
          }
          // For named entities, return as-is (would need htmlEntities map)
          return match;
        } catch (e) {
          return match;
        }
      }
    );
  }

  /**
   * Decode only Unicode escape sequences
   */
  private static decodePartialUnicode(input: string): string {
    return input.replace(/\\u[0-9A-Fa-f]{4}/g, (match) => {
      try {
        return String.fromCharCode(parseInt(match.slice(2), 16));
      } catch (e) {
        return match;
      }
    });
  }

  /**
   * Decode JavaScript escape sequences
   */
  private static decodePartialJsEscape(input: string): string {
    return input.replace(
      /\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g,
      (match) => {
        try {
          if (match.startsWith("\\x")) {
            // Hex escape
            return String.fromCharCode(parseInt(match.slice(2), 16));
          } else if (match.startsWith("\\u")) {
            // Unicode escape
            return String.fromCharCode(parseInt(match.slice(2), 16));
          } else {
            // Octal escape
            return String.fromCharCode(parseInt(match.slice(1), 8));
          }
        } catch (e) {
          return match;
        }
      }
    );
  }

  /**
   * Find potential hex sequences and try to decode them
   */
  private static decodePartialRawHex(input: string): string {
    return input.replace(/[0-9A-Fa-f]{2,}/g, (match) => {
      try {
        // Only attempt to decode if it's an even length hex string
        if (match.length % 2 === 0) {
          let decoded = "";
          for (let i = 0; i < match.length; i += 2) {
            const hexPair = match.substring(i, i + 2);
            const charCode = parseInt(hexPair, 16);
            // Only convert if it's a printable ASCII character
            if (charCode >= 32 && charCode <= 126) {
              decoded += String.fromCharCode(charCode);
            } else {
              // Non-printable character, abort and return original
              return match;
            }
          }
          return decoded;
        }
        return match;
      } catch (e) {
        return match;
      }
    });
  }

  /**
   * Attempts to decode a string with mixed encoding types
   * @param input - String with mixed encodings
   * @returns Decoded string
   */
  static decodeMixed(input: string): string {
    try {
      // Common encoding types that might be mixed
      const commonTypes: ENC_TYPE[] = [
        "percentEncoding",
        "base64",
        "unicode",
        "jsEscape",
      ];

      // Apply partial decoding for each common type
      let result = input;
      for (const type of commonTypes) {
        result = this.decodePartial(result, type);
      }

      return result;
    } catch (e) {
      AppLogger.warn("Mixed decode error:", e);
      return input;
    }
  }

  /**
   * Decode mixed content (percent-encoded and Base64 parts)
   */
  static decodeMixedContent(input: string): string {
    let result = input;

    // First pass: decode percent encoding
    if (/%[0-9A-Fa-f]{2}/.test(result)) {
      result = this.decodePartial(result, "percentEncoding");
    }

    // Second pass: decode base64 segments
    if (/[A-Za-z0-9+\/=]{4,}/.test(result)) {
      result = this.decodePartial(result, "base64");
    }

    // Third pass: decode hex escapes
    if (/\\x[0-9A-Fa-f]{2}/.test(result)) {
      result = this.decodePartial(result, "jsEscape");
    }

    return result;
  }

  /**
   * Try to partially decode with a specific encoding type
   * Returns success status and decoded parts
   */
  static tryPartialDecode(
    input: string,
    encodingType: ENC_TYPE
  ): {
    success: boolean;
    decoded?: string;
    parts?: string[];
  } {
    try {
      const decoded = this.decodePartial(input, encodingType);
      const success = decoded !== input; // Changed if decoding worked

      return {
        success,
        decoded: success ? decoded : undefined,
      };
    } catch (e) {
      return { success: false };
    }
  }
}
