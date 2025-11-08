/**
 * Escape Sequence Decoding Module
 * Handles JavaScript, CSS, and character escape sequences
 */

import { AppLogger } from "../../../common/AppLogger";

export class EscapeDecoder {
  /**
   * Decodes JavaScript escape sequences
   */
  static decodeJsEscape(input: string): string {
    if (!input.includes("\\")) return input;

    try {
      // Handle various JavaScript escape sequences
      return input.replace(
        /\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[0-7]{1,3}|.)/g,
        (match, escape) => {
          if (escape.startsWith("x")) {
            // Hex escape \xFF
            return String.fromCharCode(parseInt(escape.substring(1), 16));
          } else if (escape.startsWith("u")) {
            // Unicode escape \uFFFF
            return String.fromCharCode(parseInt(escape.substring(1), 16));
          } else if (/^[0-7]+$/.test(escape)) {
            // Octal escape \000
            return String.fromCharCode(parseInt(escape, 8));
          } else {
            // Single character escapes like \n, \t, etc.
            switch (escape) {
              case "n":
                return "\n";
              case "t":
                return "\t";
              case "r":
                return "\r";
              case "b":
                return "\b";
              case "f":
                return "\f";
              case "v":
                return "\v";
              case "0":
                return "\0";
              default:
                return escape; // For \", \', \\, etc.
            }
          }
        }
      );
    } catch (e) {
      AppLogger.warn("JS escape decode error:", e);
      return input;
    }
  }

  /**
   * Decodes character escapes (JavaScript/C-style)
   */
  static decodeCharacterEscapes(input: string): string {
    // Handle JavaScript/C-style character escapes: \x74\x72\x75\x65
    return input.replace(
      /\\x([0-9A-Fa-f]{2})|\\([0-7]{1,3})|\\u([0-9A-Fa-f]{4})/g,
      (match, hex, octal, unicode) => {
        if (hex) {
          return String.fromCharCode(parseInt(hex, 16));
        } else if (octal) {
          return String.fromCharCode(parseInt(octal, 8));
        } else if (unicode) {
          return String.fromCharCode(parseInt(unicode, 16));
        }
        return match;
      }
    );
  }

  /**
   * Decodes CSS escape sequences
   */
  static decodeCssEscape(input: string): string {
    return (
      input
        // Handle Unicode escapes with variable-length hex digits
        .replace(/\\([0-9A-Fa-f]{1,6})\s?/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        // Handle simple character escapes (any non-hex character that's escaped)
        .replace(/\\(.)/g, (_, char) => char)
    );
  }

  /**
   * Decodes Quoted-Printable encoded text
   */
  static decodeQuotedPrintable(input: string): string {
    // Remove soft line breaks (=<CR><LF>)
    let cleanInput = input.replace(/=(?:\r\n|\n|\r)/g, "");

    // Decode =XX sequences
    return cleanInput.replace(/=([0-9A-F]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }
}
