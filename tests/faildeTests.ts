/*Manual testing failed tests */

import NDS from "../src/services/StrlDec.service.js";

function runTest() {
  function assertEqual(received: string, expected: string, name: string) {
    if (received === expected) {
      console.log(`✅ Passed: ${name}`);
      return;
    }
    console.error(
      `📍❌ NehonixLib ${name.toLocaleLowerCase()} for "${expected}" but we received "${received}" `,
    );
    console.error(
      "Details: ",
      {
        received,
        expected,
        name,
      },
      "\n",
    );
  }
  {
    //1. Should decode hex string correctly (specific method)
    const rawHexInput =
      "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374";
    const expected = "https://app.nehosell.com/auth/login?test";
    assertEqual(
      NDS.decode({ input: rawHexInput, encodingType: "hex" }),
      expected,
      "Should decode hex string correctly (specific method)",
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(rawHexInput).val(),
      expected,
      "Should decode hex string correctly (auto-detect)",
    );
  }
  {
    //Should decode rot13 correctly (auto-detect)
    const rot13Input = "uggcf://ncc.punevbj.pbz/nhgu/ybtva?grfg";
    const expected = "https://app.nehosell.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: rot13Input, encodingType: "rot13" }),
      expected,
      "Should decode rot13 correctly (specific method)",
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(rot13Input).val(),
      expected,
      "Should decode rot13 correctly (auto-detect)",
    );
  }
  {
    //Should decode double-nested base64
    const doubleB64 =
      "YUhSMGNITTZMeTloY0hBdVkyaGhjbWx2ZHk1amIyMHZZWFYwYUM5c2IyZHBiajkwWlhOMQ==";
    const expected = "https://app.nehosell.com/auth/login?tesu";

    assertEqual(
      NDS.decodeAnyToPlaintext(doubleB64).val(),
      expected,
      "Should decode double-nested base64",
    );
  }
  {
    //Should decode hex within URL encoding
    const hexInUrl =
      "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374%3D";
    const expected = "https://app.nehosell.com/auth/login?test=";

    assertEqual(
      NDS.decodeAnyToPlaintext(hexInUrl).val(),
      expected,
      "Should decode hex within URL encoding",
    );
  }

  {
    //5 Should decode triple-nested encodings

    const tripleNested = "ZUhKMFkzTTBNQSUzRCUzRA==";
    const expected = "xrtcs40";

    assertEqual(
      NDS.decodeAnyToPlaintext(tripleNested).val(),
      expected,
      "Should decode triple-nested encodings",
    );
  }

  {
    //6 Should handle urlWithComplexEnc2 correctly
    const urlWithComplexEnc2 =
      "https://app.nehosell.com/stores?test=68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374&&test2=https%3A%2F%2Fapp.nehosell.com%2Fauth%2Flogin%3Ftes";
    const expected =
      "https://app.nehosell.com/stores?test=https://app.nehosell.com/auth/login?test&&test2=https://app.nehosell.com/auth/login?tes";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithComplexEnc2).val(),
      expected,
      "Should handle urlWithComplexEnc2 correctly",
    );
  }
}

runTest();
