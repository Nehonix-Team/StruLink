import NDS from "./services/StrlDec.service";
import { ncu } from "./utils/NehonixCoreUtils";
import { NehonixSafetyLayer } from "./utils/NehonixSafetyLayer";
import { StruLink } from "./StruLink";

export { StruLink };
//v2
export { MaliciousPatternType } from "./services/MaliciousPatterns.service";
export type { MaliciousPatternResult } from "./services/MaliciousPatterns.service";
/**
 * Encodes user input based on the context in which it will be used
 * Selects the appropriate encoding method for security and compatibility
 *
 * @param input The user input to secure
 * @param context The context where the input will be used
 * @param options Optional configuration for specific encoding behaviors
 * @returns The appropriately encoded string
 */
export const __safeEncode__ = NehonixSafetyLayer.__safeEncode__;
export { StruLink as __strl__ };
export const decodeB64 = (input: string) =>
  NDS.decode({
    input,
    encodingType: "base64",
  });

//v2.3.x - Integration exports removed (Express/React)
export type { DetectedPattern } from "./services/MaliciousPatterns.service";
export const { detectDuplicatedValues: detectDuplicateUrlParams } = ncu;
export { PATTERNS } from "./utils/attacks_parttens";