/**
 * Test for EncodingDetector module
 * Verifies the extracted detection logic works correctly
 */

import { EncodingDetector } from "../src/services/decoder/core/EncodingDetector";

console.log("Testing EncodingDetector Module\n" + "=".repeat(60));

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

// Base64 Detection
test("Detect Base64", () => {
  const result = EncodingDetector.detectEncoding("SGVsbG8gV29ybGQ=");
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely === "base64";
});

// Hex Detection
test("Detect Raw Hex", () => {
  const result = EncodingDetector.detectEncoding("72616e646f6d");
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely === "rawHexadecimal";
});

// Percent Encoding Detection
test("Detect Percent Encoding", () => {
  const result = EncodingDetector.detectEncoding("hello%20world");
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely.includes("percent") || result.mostLikely.includes("Percent");
});

// Base32 Detection
test("Detect Base32", () => {
  const result = EncodingDetector.detectEncoding("OJQW4ZDPNU======");
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely === "base32";
});

// Unicode Detection
test("Detect Unicode", () => {
  const result = EncodingDetector.detectEncoding("\\u0048\\u0065\\u006c\\u006c\\u006f");
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely.includes("unicode");
});

// Plain Text Detection
test("Detect Plain Text", () => {
  const result = EncodingDetector.detectEncoding("hello world");
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely === "plainText" || result.mostLikely.includes("partial");
});

// JWT Detection
test("Detect JWT", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  const result = EncodingDetector.detectEncoding(jwt);
  console.log(`  Detected: ${result.mostLikely} (${result.confidence.toFixed(2)})`);
  return result.mostLikely === "jwt";
});

console.log("\n" + "=".repeat(60));
console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(2)}%`);

if (failed === 0) {
  console.log("\n🎉 All EncodingDetector tests passed!");
  process.exit(0);
} else {
  console.log("\n⚠️  Some tests failed");
  process.exit(1);
}
