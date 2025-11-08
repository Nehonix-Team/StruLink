import { __strl__ } from "../src/index";

const shortHex = "72616e646f6d"; // "random" in hex - 12 chars
const longHex = "48656c6c6f20776f726c64"; // "Hello World" in hex - 22 chars

console.log("=".repeat(60));
console.log("SHORT HEX TEST");
console.log("=".repeat(60));
console.log("Input:", shortHex);
console.log("Length:", shortHex.length);
const shortDetection = __strl__.detectEncoding(shortHex);
console.log("Detected as:", shortDetection.mostLikely);
console.log("Confidence:", shortDetection.confidence);
console.log("All types:", shortDetection.types);
console.log("");

console.log("=".repeat(60));
console.log("LONG HEX TEST");
console.log("=".repeat(60));
console.log("Input:", longHex);
console.log("Length:", longHex.length);
const longDetection = __strl__.detectEncoding(longHex);
console.log("Detected as:", longDetection.mostLikely);
console.log("Confidence:", longDetection.confidence);
console.log("All types:", longDetection.types);
