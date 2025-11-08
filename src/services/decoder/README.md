# Decoder Modules

This directory contains the modular decoder implementation for StruLink.

## Structure

```
decoder/
├── core/               # Core decoding logic (TODO)
│   ├── EncodingDetector.ts
│   ├── DecoderCore.ts
│   └── PartialDecoder.ts
├── decoders/          # Specialized decoders
│   ├── Base64Decoder.ts       ✅ Implemented
│   ├── Base32Decoder.ts       ✅ Implemented
│   ├── HexDecoder.ts          ✅ Implemented
│   ├── PercentDecoder.ts      ✅ Implemented
│   ├── UnicodeDecoder.ts      ⏳ TODO
│   ├── HtmlDecoder.ts         ⏳ TODO
│   ├── EscapeDecoder.ts       ⏳ TODO
│   ├── SpecialDecoder.ts      ⏳ TODO
│   └── index.ts
├── url/               # URL-specific processing (TODO)
│   ├── UrlParameterDecoder.ts
│   ├── UrlProcessor.ts
│   └── index.ts
└── README.md
```

## Usage

```typescript
import { Base64Decoder, HexDecoder } from "./decoder/decoders";

// Decode Base64
const decoded = Base64Decoder.decodeBase64("SGVsbG8gV29ybGQ=");

// Decode Hex
const hexDecoded = HexDecoder.decodeHex("48656c6c6f");
```

## Migration Status

This is part of the ongoing refactoring of `StrlDec.service.ts` (2,344 lines) into smaller, maintainable modules.

**Current Status**: Phase 1 - Decoder Extraction (In Progress)

See [REFACTORING_PLAN.md](../../../docs/REFACTORING_PLAN.md) for full details.

## Contributing

When adding new decoders:
1. Create a new file in `decoders/` directory
2. Follow the naming convention: `[Type]Decoder.ts`
3. Export the class in `decoders/index.ts`
4. Add tests for the new decoder
5. Update this README

## Notes

- All decoders are static classes for simplicity
- Each decoder handles one or more related encoding types
- Error handling is consistent across all decoders
- UTF-8 is the default output encoding
