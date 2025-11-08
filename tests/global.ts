import { __strl__ } from "../src/index";

console.log("============ TEST1: B64 AUTO DECODE");
const b64Text = __strl__.encode("Hello World", "base64");
console.log("b64Text: ", b64Text);
const b64TextAutoDecode = __strl__.autoDetectAndDecode(b64Text).val();
console.log("b64TextAutoDecode: ", b64TextAutoDecode);

if (b64Text !== b64TextAutoDecode) {
  console.log("TEST 1: PASSED");
} else {
  console.log("TEST 1: FAILED");
}

console.log("============ TEST2: HEX AUTO DECODE");
const hexText = __strl__.encode("Hello World", "hex");
console.log("hexText: ", hexText);
const hexTextAutoDecode = __strl__.autoDetectAndDecode(hexText).val();
console.log("hexTextAutoDecode: ", hexTextAutoDecode);
if (hexText !== hexTextAutoDecode) {
  console.log("TEST 2: PASSED");
} else {
  console.log("TEST 2: FAILED");
}

console.log("============ TEST3: RAWHEX AUTO DECODE");
const rawHexText = __strl__.encode("random", "rawHex");
console.log("rawHexText: ", rawHexText);
const rawHexTextAutoDecode = __strl__.autoDetectAndDecode(rawHexText).val();
console.log("rawHexTextAutoDecode: ", rawHexTextAutoDecode);

if (rawHexText !== rawHexTextAutoDecode) {
  console.log("TEST 3: PASSED");
} else {
  console.log("TEST 3: FAILED");
}
