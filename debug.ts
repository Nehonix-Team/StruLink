const doubleB64 =
  "YUhSMGNITTZMeTloY0hBdVkyaGhjbWx2ZHk1amIyMHZZWFYwYUM5c2IyZHBiajkwWlhOMQ==";
const once = Buffer.from(doubleB64, "base64").toString();
const twice = Buffer.from(once, "base64").toString();
console.log("twice:", twice);

const hexInUrl =
  "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374%3D";
console.log("hex in url decoded:", decodeURIComponent(hexInUrl));

const tripleNested = "ZUhKMFkzTTBNQSUzRCUzRA==";
console.log("triple - once:", Buffer.from(tripleNested, "base64").toString());
