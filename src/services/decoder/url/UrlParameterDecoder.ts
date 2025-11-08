/**
 * URL Parameter Decoder Module
 * Handles decoding of URL query parameters with various encodings
 * 
 * Extracted from StrlDec.service.ts (~80 lines)
 */

import { AppLogger } from "../../../common/AppLogger";
import { UrlProcessor } from "./UrlProcessor";
import { PartialDecoder } from "../core/PartialDecoder";
import {
  Base64Decoder,
  HexDecoder,
  PercentDecoder,
} from "../decoders";

export class UrlParameterDecoder {
  /**
   * Decodes URL parameters intelligently
   * Detects and decodes various encoding types in URL parameters
   * 
   * @param url - URL with potentially encoded parameters
   * @returns URL with decoded parameters
   */
  static decodeUrlParameters(url: string): string {
    // Basic validation
    if (!url.includes("?")) return url;
    
    try {
      const urlParts = UrlProcessor.splitUrl(url);
      if (!urlParts) return url;

      const { baseUrl, queryString } = urlParts;
      const params = UrlProcessor.parseQueryParams(queryString);
      const separator = UrlProcessor.detectSeparator(queryString);
      
      let modified = false;
      const decodedParams: string[] = [];

      for (const { key, value, original } of params) {
        // Skip empty or very short values
        if (!value || value.length < 3) {
          decodedParams.push(original);
          continue;
        }

        // Try to decode the value
        const decoded = this.decodeParameterValue(value);
        
        if (decoded !== value) {
          modified = true;
          decodedParams.push(`${key}=${decoded}`);
        } else {
          decodedParams.push(original);
        }
      }

      return modified ? `${baseUrl}?${decodedParams.join(separator)}` : url;
    } catch (e) {
      AppLogger.warn("Error decoding URL parameters:", e);
      return url;
    }
  }

  /**
   * Decodes a single parameter value
   * Tries multiple encoding types
   */
  private static decodeParameterValue(value: string): string {
    // Detect encoding type
    const encodingType = UrlProcessor.detectParameterEncoding(value);
    
    if (!encodingType) {
      return value;
    }

    try {
      let decoded = value;

      // Try specific decoder based on detected type
      switch (encodingType) {
        case "percentEncoding":
          decoded = PercentDecoder.decodePercentEncoding(value);
          break;
          
        case "base64":
          if (value.length % 4 === 0) {
            decoded = Base64Decoder.decodeBase64(value);
          }
          break;
          
        case "rawHexadecimal":
          if (value.length % 2 === 0) {
            decoded = HexDecoder.decodeRawHex(value);
          }
          break;
          
        default:
          // Try partial decoding for other types
          decoded = PartialDecoder.decodePartial(value, encodingType);
      }

      // Verify the decoded result is printable
      if (decoded !== value && UrlProcessor.isPrintable(decoded, 0.8)) {
        return decoded;
      }
    } catch (e) {
      // Decoding failed, return original
    }

    return value;
  }

  /**
   * Decodes all parameters in a URL using auto-detection
   * More aggressive than decodeUrlParameters
   */
  static decodeAllParameters(url: string, maxIterations: number = 3): string {
    let result = url;
    let iteration = 0;

    while (iteration < maxIterations) {
      const decoded = this.decodeUrlParameters(result);
      
      if (decoded === result) {
        // No more changes
        break;
      }
      
      result = decoded;
      iteration++;
    }

    return result;
  }
}
