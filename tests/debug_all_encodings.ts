import { __strl__ } from "../src/index";

const testString = "random";

const encodingTypes = [
  "base64",
  "base32",
  "rawHex",
  "hex",
  "percentEncoding",
  "unicode",
  "htmlEntity",
  "rot13",
  "asciihex",
  "asciioct",
] as const;

console.log("Testing auto-detection for short string:", testString);
console.log("=".repeat(70));

for (const encoding of encodingTypes) {
  try {
    const encoded = __strl__.encode(testString, encoding);
    const detection = __strl__.detectEncoding(encoded);
    const decoded = __strl__.autoDetectAndDecode(encoded).val();
    
    const success = decoded === testString;
    const status = success ? "✅ PASS" : "❌ FAIL";
    
    console.log(`\n${encoding.toUpperCase()}`);
    console.log(`  Encoded: ${encoded}`);
    console.log(`  Detected as: ${detection.mostLikely} (confidence: ${detection.confidence.toFixed(2)})`);
    console.log(`  Decoded: ${decoded}`);
    console.log(`  ${status}`);
  } catch (error) {
    console.log(`\n${encoding.toUpperCase()}`);
    console.log(`  ❌ ERROR: ${error}`);
  }
}

console.log("\n" + "=".repeat(70));
