# Core Decoder Logic Modules

This directory contains the core detection and orchestration logic extracted from `StrlDec.service.ts`.

## Status: Phase 2 - In Progress

### Modules

#### EncodingDetector.ts ⏳ Extracted (Integration Pending)
- **Purpose**: Automatic encoding type detection with confidence scoring
- **Size**: ~400 lines
- **Status**: Code extracted, needs integration to avoid circular dependencies
- **Key Methods**:
  - `detectEncoding()` - Main detection algorithm
  - `detectNestedEncoding()` - Nested encoding detection
  - `detectPercentEncoding()` - Percent encoding patterns
  - `detectUrlEncodings()` - URL parameter encodings
  - `runStandardDetectionChecks()` - Standard encoding checks

#### DecoderCore.ts ⏳ TODO
- **Purpose**: Main decoding orchestration
- **Size**: ~200 lines (estimated)
- **Methods**: `decode()`, `decodeAnyToPlaintext()`, `decodeSingle()`

#### PartialDecoder.ts ✅ Implemented
- **Purpose**: Partial and mixed encoding decoding
- **Size**: ~260 lines
- **Status**: Fully functional and tested
- **Key Methods**:
  - `decodePartial()` - Decode partially encoded strings
  - `decodeMixed()` - Handle mixed encoding types
  - `decodeMixedContent()` - Decode mixed percent/base64 content
  - `tryPartialDecode()` - Attempt partial decode with validation

## Integration Strategy

The core modules have complex dependencies on:
- `NehonixSharedUtils` - Utility functions
- `NehonixCoreUtils` - URL validation
- Decoder modules - For verification

### Integration Plan

1. **Phase 2a**: Extract modules (current)
2. **Phase 2b**: Refactor dependencies to break circular imports
3. **Phase 2c**: Update StrlDec.service.ts to use core modules
4. **Phase 2d**: Test and verify no breaking changes

## Notes

- Circular dependency issues need to be resolved before full integration
- EncodingDetector is self-contained but needs utility function access
- Will integrate gradually to maintain stability

## Next Steps

1. Create dependency injection or factory pattern for utilities
2. Extract DecoderCore and PartialDecoder
3. Refactor StrlDec.service.ts to use all core modules
4. Comprehensive testing

---

See [REFACTORING_PLAN.md](../../../../docs/REFACTORING_PLAN.md) for overall strategy.
