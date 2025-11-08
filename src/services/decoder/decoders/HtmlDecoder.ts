/**
 * HTML Decoding Module
 * Handles HTML entities and decimal/hex entity decoding
 */

import { htmlEntities } from "../../../utils/html.enties";

export class HtmlDecoder {
  /**
   * Decodes HTML entities (named, decimal, and hexadecimal)
   */
  static decodeHTMLEntities(input: string): string {
    const entities: { [key: string]: string } = htmlEntities;

    // Replace named entities
    let result = input;
    for (const [entity, char] of Object.entries(entities)) {
      result = result.replace(new RegExp(entity, "g"), char);
    }

    // Replace numeric entities (decimal)
    result = result.replace(/&#(\d+);/g, (match, dec) => {
      return String.fromCodePoint(parseInt(dec, 10));
    });

    // Replace numeric entities (hexadecimal)
    result = result.replace(/&#x([0-9A-Fa-f]+);/g, (match, hex) => {
      return String.fromCodePoint(parseInt(hex, 16));
    });

    return result;
  }

  /**
   * Decodes decimal HTML entities only
   */
  static decodeDecimalHtmlEntity(input: string): string {
    return input.replace(/&#(\d+);/g, (_, dec) => {
      return String.fromCharCode(parseInt(dec, 10));
    });
  }
}
