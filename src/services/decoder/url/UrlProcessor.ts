/**
 * URL Processing Module
 * Handles URL-specific decoding operations
 * 
 * Extracted from StrlDec.service.ts
 */

import { ENC_TYPE } from "../../../types";
import { AppLogger } from "../../../common/AppLogger";
import { HexDecoder } from "../decoders/HexDecoder";

export class UrlProcessor {
  /**
   * Detects and handles raw hex-encoded URLs
   * Checks if input is a hex-encoded URL and decodes it
   * 
   * @param input - Potential hex-encoded URL
   * @returns Decoded URL or original input
   */
  static detectAndHandleRawHexUrl(input: string): string {
    // Check if input matches a hex pattern for a URL
    if (/^[0-9A-Fa-f]+$/.test(input) && input.length % 2 === 0) {
      try {
        const decoded = HexDecoder.decodeRawHex(input);
        
        // Check if decoded result looks like a URL
        if (decoded.includes("://") || decoded.startsWith("http")) {
          return decoded;
        }
      } catch (e) {
        // Not a valid hex URL, return original
      }
    }
    
    return input;
  }

  /**
   * Checks if a string is a valid URL
   * Simple validation without external dependencies
   */
  static isValidUrl(input: string): boolean {
    try {
      new URL(input);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Extracts base URL and query string
   */
  static splitUrl(url: string): { baseUrl: string; queryString: string } | null {
    if (!url.includes("?")) return null;
    
    const [baseUrl, queryString] = url.split("?", 2);
    return queryString ? { baseUrl, queryString } : null;
  }

  /**
   * Parses query parameters preserving && separators
   */
  static parseQueryParams(queryString: string): Array<{ key: string; value: string; original: string }> {
    const params = queryString.split(/&{1,2}/);
    
    return params.map(param => {
      if (param.includes("=")) {
        const [key, value] = param.split("=", 2);
        return { key, value, original: param };
      }
      return { key: param, value: "", original: param };
    });
  }

  /**
   * Detects the separator used in query string (& or &&)
   */
  static detectSeparator(queryString: string): string {
    return queryString.includes("&&") ? "&&" : "&";
  }

  /**
   * Checks if a value is printable (mostly ASCII)
   */
  static isPrintable(value: string, threshold: number = 0.8): boolean {
    if (!value || value.length === 0) return false;
    
    const printableRatio = value.replace(/[^\x20-\x7E]/g, "").length / value.length;
    return printableRatio > threshold;
  }

  /**
   * Detects encoding type in a URL parameter value
   */
  static detectParameterEncoding(value: string): ENC_TYPE | null {
    if (!value || value.length < 3) return null;

    const encodingPatterns: Array<{ type: ENC_TYPE; pattern: RegExp }> = [
      { type: "percentEncoding", pattern: /%[0-9A-Fa-f]{2}/ },
      { type: "base64", pattern: /^[A-Za-z0-9+/=]{4,}$/ },
      { type: "rawHexadecimal", pattern: /^[0-9A-Fa-f]{6,}$/ },
      { type: "unicode", pattern: /\\u[0-9A-Fa-f]{4}/ },
      { type: "jsEscape", pattern: /\\x[0-9A-Fa-f]{2}/ },
    ];

    for (const { type, pattern } of encodingPatterns) {
      if (pattern.test(value)) {
        return type;
      }
    }

    return null;
  }
}
