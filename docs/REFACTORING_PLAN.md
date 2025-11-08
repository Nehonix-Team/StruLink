# StrlDec.service.ts Refactoring Plan

## Current State
- **File**: `src/services/StrlDec.service.ts`
- **Size**: 2,344 lines
- **Issue**: Too large, difficult to maintain

## Proposed Modular Structure

```
src/services/decoder/
├── core/
│   ├── EncodingDetector.ts      # 460+ lines - detectEncoding, detectNestedEncoding
│   ├── DecoderCore.ts            # 200+ lines - Main decode orchestration
│   └── PartialDecoder.ts         # 150+ lines - Partial decoding logic
├── decoders/
│   ├── Base64Decoder.ts          # Base64, urlSafeBase64
│   ├── Base32Decoder.ts          # Base32
│   ├── HexDecoder.ts             # Hex, rawHex, asciiHex, asciiOct
│   ├── PercentDecoder.ts         # Percent encoding, double percent
│   ├── UnicodeDecoder.ts         # Unicode, UTF-7
│   ├── HtmlDecoder.ts            # HTML entities, decimal entities
│   ├── EscapeDecoder.ts          # JS escape, CSS escape
│   ├── SpecialDecoder.ts         # ROT13, JWT, Punycode, Quoted-Printable
│   └── index.ts                  # Export all decoders
├── url/
│   ├── UrlParameterDecoder.ts    # URL parameter decoding
│   ├── UrlProcessor.ts           # URL-specific processing
│   └── index.ts
└── StrlDec.service.ts            # Main orchestrator (~200 lines)
```

## Benefits

1. **Maintainability**: Each module focuses on specific encoding types
2. **Testability**: Individual decoders can be tested in isolation
3. **Readability**: Smaller files are easier to understand
4. **Scalability**: Easy to add new encoding types
5. **Performance**: Potential for lazy loading modules

## Implementation Strategy

### Phase 1: Extract Decoder Modules (Priority: High)
- ✅ Base64Decoder.ts
- ✅ Base32Decoder.ts
- ⏳ HexDecoder.ts
- ⏳ PercentDecoder.ts
- ⏳ UnicodeDecoder.ts
- ⏳ HtmlDecoder.ts
- ⏳ EscapeDecoder.ts
- ⏳ SpecialDecoder.ts

### Phase 2: Extract Core Logic (Priority: High)
- ⏳ EncodingDetector.ts - Detection algorithms
- ⏳ DecoderCore.ts - Main decode method
- ⏳ PartialDecoder.ts - Partial decoding

### Phase 3: Extract URL Processing (Priority: Medium)
- ⏳ UrlParameterDecoder.ts
- ⏳ UrlProcessor.ts

### Phase 4: Update Main Service (Priority: High)
- ⏳ Refactor StrlDec.service.ts to use modules
- ⏳ Maintain backward compatibility

### Phase 5: Testing & Validation (Priority: Critical)
- ⏳ Run comprehensive test suite
- ⏳ Verify no breaking changes
- ⏳ Performance benchmarking

## Migration Notes

- All public APIs must remain unchanged
- Internal methods can be refactored
- Maintain export compatibility with existing code
- Add deprecation warnings if needed

## Timeline

- **Phase 1-2**: Immediate (critical modules)
- **Phase 3**: Next iteration
- **Phase 4-5**: Before next release

## Status

- **Started**: 2025-11-08
- **Current Phase**: Phase 1 (In Progress)
- **Completion**: TBD
