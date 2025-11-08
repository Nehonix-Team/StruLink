/**
 * Base64 Decoding Module
 * Handles Base64 and URL-safe Base64 decoding
 */

export class Base64Decoder {
  /**
   * Decodes standard Base64 encoded text
   */
  static decodeBase64(input: string): string {
    try {
      return Buffer.from(input, "base64").toString("utf-8");
    } catch (e) {
      throw new Error(`Base64 decode error: ${e}`);
    }
  }

  /**
   * Decodes URL-safe Base64 encoded text
   */
  static decodeUrlSafeBase64(input: string): string {
    // Convert URL-safe characters back to standard Base64
    const standardBase64 = input
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      // Add padding if needed
      .padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");

    return this.decodeBase64(standardBase64);
  }
}
