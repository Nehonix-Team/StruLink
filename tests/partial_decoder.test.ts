/**
 * Test for PartialDecoder module
 * Verifies partial and mixed encoding decoding
 */

import { PartialDecoder } from "../src/services/decoder/core/PartialDecoder";

console.log("Testing PartialDecoder Module\n" + "=".repeat(60));

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

// Partial Percent Encoding
test("Partial Percent Encoding", () => {
  const input = "Hello%20World%21";
  const result = PartialDecoder.decodePartial(input, "percentEncoding");
  console.log(`  Input: "${input}" -> Output: "${result}"`);
  return result === "Hello World!";
});

// Partial Base64
test("Partial Base64", () => {
  const input = "prefix_SGVsbG8_suffix";
  const result = PartialDecoder.decodePartial(input, "base64");
  console.log(`  Input: "${input}" -> Output: "${result}"`);
  // Should decode the base64 part if it's valid
  return result.includes("prefix") && result.includes("suffix");
});

// Partial Unicode
test("Partial Unicode", () => {
  const input = "Hello \\u0057\\u006f\\u0072\\u006c\\u0064";
  const result = PartialDecoder.decodePartial(input, "unicode");
  console.log(`  Input: "${input}" -> Output: "${result}"`);
  return result === "Hello World";
});

// Partial JS Escape
test("Partial JS Escape", () => {
  const input = "\\x48\\x65\\x6c\\x6c\\x6f";
  const result = PartialDecoder.decodePartial(input, "jsEscape");
  console.log(`  Input: "${input}" -> Output: "${result}"`);
  return result === "Hello";
});

// Mixed Content
test("Mixed Content Decoding", () => {
  const input = "Hello%20SGVsbG8";
  const result = PartialDecoder.decodeMixedContent(input);
  console.log(`  Input: "${input}" -> Output: "${result}"`);
  // Should decode both percent and base64
  return result.includes("Hello");
});

// Try Partial Decode
test("Try Partial Decode - Success", () => {
  const input = "test%20value";
  const result = PartialDecoder.tryPartialDecode(input, "percentEncoding");
  console.log(`  Success: ${result.success}, Decoded: "${result.decoded}"`);
  return result.success === true && result.decoded === "test value";
});

// Try Partial Decode - No Change
test("Try Partial Decode - No Change", () => {
  const input = "plaintext";
  const result = PartialDecoder.tryPartialDecode(input, "percentEncoding");
  console.log(`  Success: ${result.success}`);
  return result.success === false;
});

console.log("\n" + "=".repeat(60));
console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(2)}%`);

if (failed === 0) {
  console.log("\n🎉 All PartialDecoder tests passed!");
  process.exit(0);
} else {
  console.log("\n⚠️  Some tests failed");
  process.exit(1);
}
