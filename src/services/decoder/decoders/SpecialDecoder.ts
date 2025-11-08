/**
 * Special Encoding Decoders Module
 * Handles ROT13, JWT, Punycode, and other special encodings
 */

import punycode from "punycode";

export class SpecialDecoder {
  /**
   * Decodes ROT13 encoded text
   */
  static decodeRot13(input: string): string {
    return input.replace(/[a-zA-Z]/g, (char) => {
      const code = char.charCodeAt(0);
      const base = char <= "Z" ? 65 : 97;
      return String.fromCharCode(((code - base + 13) % 26) + base);
    });
  }

  /**
   * Decodes JWT (JSON Web Token)
   */
  static decodeJWT(input: string): string {
    const parts = input.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    try {
      // Decode only header and payload (not signature)
      // Use Buffer directly to avoid circular dependency
      const header = Buffer.from(
        parts[0].replace(/-/g, "+").replace(/_/g, "/"),
        "base64"
      ).toString("utf-8");
      const payload = Buffer.from(
        parts[1].replace(/-/g, "+").replace(/_/g, "/"),
        "base64"
      ).toString("utf-8");

      // Format as JSON for better readability
      const headerObj = JSON.parse(header);
      const payloadObj = JSON.parse(payload);

      return JSON.stringify(
        {
          header: headerObj,
          payload: payloadObj,
          signature: "[signature]", // Don't decode the signature
        },
        null,
        2
      );
    } catch (e: any) {
      throw new Error(`JWT decoding failed: ${e.message}`);
    }
  }

  /**
   * Decodes Punycode (internationalized domain names)
   */
  static decodePunycode(input: string): string {
    try {
      // For URLs with international domains
      return input.replace(/xn--[a-z0-9-]+/g, (match) => {
        try {
          return punycode.decode(match.replace("xn--", ""));
        } catch {
          return match;
        }
      });
    } catch (e: any) {
      throw new Error(`Punycode decoding failed: ${e.message}`);
    }
  }
}
