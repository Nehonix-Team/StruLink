/**
 * Base32 Decoding Module
 */

export class Base32Decoder {
  /**
   * Decodes Base32 encoded text
   */
  static decodeBase32(input: string): string {
    // Base32 alphabet (RFC 4648)
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // Remove padding
    input = input.replace(/=+$/, "");

    let bits = "";
    for (const char of input.toUpperCase()) {
      const index = alphabet.indexOf(char);
      if (index === -1) throw new Error(`Invalid Base32 character: ${char}`);
      bits += index.toString(2).padStart(5, "0");
    }

    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.substr(i, 8), 2));
    }

    return Buffer.from(bytes).toString("utf-8");
  }
}
