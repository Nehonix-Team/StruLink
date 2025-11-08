/**
 * Percent Encoding Decoding Module
 * Handles URL percent encoding and double percent encoding
 */

export class PercentDecoder {
  /**
   * Decodes percent encoding (URL encoding)
   */
  static decodePercentEncoding(input: string): string {
    try {
      return decodeURIComponent(input);
    } catch (e: any) {
      // Fallback for malformed percent encoding
      try {
        return input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
          return String.fromCharCode(parseInt(hex, 16));
        });
      } catch {
        return input;
      }
    }
  }

  /**
   * Decodes double percent encoding
   */
  static decodeDoublePercentEncoding(input: string): string {
    // First decode to get single percent encoding
    const singleEncoded = this.decodePercentEncoding(input);
    // Then decode again to get plain text
    return this.decodePercentEncoding(singleEncoded);
  }
}
