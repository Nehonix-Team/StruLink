/**
 * Unicode Decoding Module
 * Handles Unicode escape sequences and UTF-7 encoding
 */

export class UnicodeDecoder {
  /**
   * Decodes Unicode escape sequences (\uXXXX and \u{XXXXX})
   */
  static decodeUnicode(input: string): string {
    try {
      // Replace \uXXXX and \u{XXXXX} with their equivalent characters
      return input
        .replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
          return String.fromCodePoint(parseInt(hex, 16));
        })
        .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (match, hex) => {
          return String.fromCodePoint(parseInt(hex, 16));
        });
    } catch (e: any) {
      throw new Error(`Unicode decoding failed: ${e.message}`);
    }
  }

  /**
   * Decodes UTF-7 encoded text
   */
  static decodeUtf7(input: string): string {
    let result = "";
    let inBase64 = false;
    let base64Chars = "";

    for (let i = 0; i < input.length; i++) {
      const char = input[i];

      if (char === "+" && !inBase64) {
        // Start of Base64 sequence
        if (input[i + 1] === "-") {
          // +- represents a literal +
          result += "+";
          i++; // Skip the -
        } else {
          inBase64 = true;
          base64Chars = "";
        }
      } else if (char === "-" && inBase64) {
        // End of Base64 sequence
        inBase64 = false;
        if (base64Chars) {
          try {
            // Decode the Base64 sequence
            const decoded = Buffer.from(base64Chars, "base64").toString("utf-16be");
            result += decoded;
          } catch {
            // If decoding fails, keep original
            result += "+" + base64Chars + "-";
          }
        }
        base64Chars = "";
      } else if (inBase64) {
        // Collect Base64 characters
        base64Chars += char;
      } else {
        // Regular character
        result += char;
      }
    }

    // Handle case where Base64 sequence wasn't closed
    if (inBase64 && base64Chars) {
      try {
        const decoded = Buffer.from(base64Chars, "base64").toString("utf-16be");
        result += decoded;
      } catch {
        result += "+" + base64Chars;
      }
    }

    return result;
  }
}
