/**
 * Test for new modular decoder implementation
 * Ensures decoder modules work correctly
 */

import { Base64Decoder, Base32Decoder, HexDecoder, PercentDecoder } from "../src/services/decoder/decoders";

console.log("Testing Modular Decoders\n" + "=".repeat(60));

let passed = 0;
let failed = 0;

function test(name: string, fn: () => boolean) {
  try {
    if (fn()) {
      console.log(`✅ ${name}`);
      passed++;
    } else {
      console.log(`❌ ${name}`);
      failed++;
    }
  } catch (error) {
    console.log(`❌ ${name} - Error: ${error}`);
    failed++;
  }
}

// Base64 Tests
test("Base64Decoder - Standard", () => {
  const result = Base64Decoder.decodeBase64("SGVsbG8gV29ybGQ=");
  return result === "Hello World";
});

test("Base64Decoder - URL Safe", () => {
  const result = Base64Decoder.decodeUrlSafeBase64("SGVsbG8gV29ybGQ");
  return result === "Hello World";
});

// Base32 Tests
test("Base32Decoder - Standard", () => {
  const result = Base32Decoder.decodeBase32("JBSWY3DPEBLW64TMMQ======");
  return result === "Hello World";
});

test("Base32Decoder - No Padding", () => {
  const result = Base32Decoder.decodeBase32("JBSWY3DPEBLW64TMMQ");
  return result === "Hello World";
});

// Hex Tests
test("HexDecoder - Standard", () => {
  const result = HexDecoder.decodeHex("48656c6c6f");
  return result === "Hello";
});

test("HexDecoder - With 0x Prefix", () => {
  const result = HexDecoder.decodeHex("0x48656c6c6f");
  return result === "Hello";
});

test("HexDecoder - Raw Hex", () => {
  const result = HexDecoder.decodeRawHex("72616e646f6d");
  return result === "random";
});

test("HexDecoder - ASCII Hex", () => {
  const result = HexDecoder.decodeAsciiHex("48656c6c6f");
  return result === "Hello";
});

test("HexDecoder - ASCII Octal", () => {
  const result = HexDecoder.decodeAsciiOct("\\110\\145\\154\\154\\157");
  return result === "Hello";
});

// Percent Encoding Tests
test("PercentDecoder - Standard", () => {
  const result = PercentDecoder.decodePercentEncoding("Hello%20World");
  return result === "Hello World";
});

test("PercentDecoder - Double Percent", () => {
  const result = PercentDecoder.decodeDoublePercentEncoding("Hello%2520World");
  return result === "Hello World";
});

test("PercentDecoder - Special Characters", () => {
  const result = PercentDecoder.decodePercentEncoding("%21%40%23%24");
  return result === "!@#$";
});

console.log("\n" + "=".repeat(60));
console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(2)}%`);

if (failed === 0) {
  console.log("\n🎉 All decoder module tests passed!");
  process.exit(0);
} else {
  console.log("\n⚠️  Some tests failed");
  process.exit(1);
}
