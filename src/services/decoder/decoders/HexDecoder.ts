/**
 * Hexadecimal Decoding Module
 * Handles various hex encoding formats
 */

export class HexDecoder {
  /**
   * Decodes standard hexadecimal encoding
   */
  static decodeHex(input: string): string {
    input = input.trim().toLowerCase();

    // Remove common hex prefixes
    if (input.startsWith("0x")) {
      input = input.substring(2);
    }

    // Ensure even length
    if (input.length % 2 !== 0) {
      throw new Error("Hex string must have even length");
    }

    const bytes: number[] = [];
    for (let i = 0; i < input.length; i += 2) {
      bytes.push(parseInt(input.substr(i, 2), 16));
    }

    return Buffer.from(bytes).toString("utf-8");
  }

  /**
   * Decodes raw hexadecimal (without prefixes or escapes)
   */
  static decodeRawHex(input: string): string {
    // For URL parameters with equals sign
    if (input.includes("=")) {
      const parts = input.split("=");
      if (parts.length === 2) {
        const key = parts[0];
        const value = parts[1];

        // Try to decode the value if it looks like hex
        if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
          try {
            const decodedValue = this.decodeHex(value);
            return `${key}=${decodedValue}`;
          } catch {
            return input;
          }
        }
      }
    }

    // Standard hex decoding
    if (/^[0-9A-Fa-f]+$/.test(input) && input.length % 2 === 0) {
      try {
        return this.decodeHex(input);
      } catch {
        return input;
      }
    }

    return input;
  }

  /**
   * Decodes ASCII hex (\\xHH format)
   */
  static decodeAsciiHex(input: string): string {
    const hexPairs = input.match(/[0-9A-Fa-f]{2}/g);
    if (!hexPairs) return input;

    return hexPairs.map((hex) => String.fromCharCode(parseInt(hex, 16))).join("");
  }

  /**
   * Decodes ASCII octal (\\OOO format)
   */
  static decodeAsciiOct(input: string): string {
    return input.replace(/\\([0-7]{3})/g, (_, oct) => {
      return String.fromCharCode(parseInt(oct, 8));
    });
  }
}
