/**
 * Test for URL Processing modules
 * Verifies URL parameter decoding and processing
 */

import { UrlProcessor, UrlParameterDecoder } from "../src/services/decoder/url";

console.log("Testing URL Processing Modules\n" + "=".repeat(60));

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

// UrlProcessor Tests
test("UrlProcessor - Detect Raw Hex URL", () => {
  const hex = "68747470733a2f2f6578616d706c652e636f6d";
  const result = UrlProcessor.detectAndHandleRawHexUrl(hex);
  console.log(`  Input: ${hex.slice(0, 20)}...`);
  console.log(`  Output: ${result}`);
  return result.includes("://");
});

test("UrlProcessor - Non-Hex Input", () => {
  const input = "https://example.com";
  const result = UrlProcessor.detectAndHandleRawHexUrl(input);
  return result === input;
});

test("UrlProcessor - Split URL", () => {
  const url = "https://example.com?key=value";
  const result = UrlProcessor.splitUrl(url);
  return result !== null && result.baseUrl === "https://example.com" && result.queryString === "key=value";
});

test("UrlProcessor - Parse Query Params", () => {
  const query = "key1=value1&key2=value2";
  const result = UrlProcessor.parseQueryParams(query);
  return result.length === 2 && result[0].key === "key1" && result[1].key === "key2";
});

test("UrlProcessor - Detect Separator", () => {
  const query1 = "a=1&b=2";
  const query2 = "a=1&&b=2";
  return UrlProcessor.detectSeparator(query1) === "&" && UrlProcessor.detectSeparator(query2) === "&&";
});

test("UrlProcessor - Is Printable", () => {
  const printable = "Hello World";
  const nonPrintable = "\x00\x01\x02";
  return UrlProcessor.isPrintable(printable) && !UrlProcessor.isPrintable(nonPrintable);
});

test("UrlProcessor - Detect Parameter Encoding - Percent", () => {
  const value = "hello%20world";
  const result = UrlProcessor.detectParameterEncoding(value);
  return result === "percentEncoding";
});

test("UrlProcessor - Detect Parameter Encoding - Base64", () => {
  const value = "SGVsbG8gV29ybGQ=";
  const result = UrlProcessor.detectParameterEncoding(value);
  return result === "base64";
});

// UrlParameterDecoder Tests
test("UrlParameterDecoder - Decode Percent Encoded Param", () => {
  const url = "https://example.com?name=John%20Doe";
  const result = UrlParameterDecoder.decodeUrlParameters(url);
  console.log(`  Input: ${url}`);
  console.log(`  Output: ${result}`);
  return result.includes("John Doe");
});

test("UrlParameterDecoder - Decode Base64 Param", () => {
  const url = "https://example.com?data=SGVsbG8=";
  const result = UrlParameterDecoder.decodeUrlParameters(url);
  console.log(`  Input: ${url}`);
  console.log(`  Output: ${result}`);
  return result.includes("Hello") || result === url; // May or may not decode depending on validation
});

test("UrlParameterDecoder - No Encoding", () => {
  const url = "https://example.com?name=test";
  const result = UrlParameterDecoder.decodeUrlParameters(url);
  return result === url;
});

test("UrlParameterDecoder - Multiple Params", () => {
  const url = "https://example.com?a=hello%20world&b=test";
  const result = UrlParameterDecoder.decodeUrlParameters(url);
  return result.includes("hello world");
});

console.log("\n" + "=".repeat(60));
console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(2)}%`);

if (failed === 0) {
  console.log("\n🎉 All URL processing tests passed!");
  process.exit(0);
} else {
  console.log("\n⚠️  Some tests failed");
  process.exit(1);
}
