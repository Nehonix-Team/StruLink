import { AppLogger } from "../../common/AppLogger";
import { NehonixSharedUtils } from "../../common/StrlCommonUtils";
import { sr } from "../../rules/security.rules";
import { MaliciousPatternOptions } from "../../services/MaliciousPatterns.service";
import NSS from "../../services/StruSecurity.service";
import {
  AsyncUrlCheckResult,
  AsyncUrlValidationOptFeature,
  AsyncUrlValidationOptions,
  ComparisonRule,
  UrlCheckResult,
  UrlValidationLevel,
  UrlValidationOptions,
  ValidUrlComponents,
} from "../../types";
import { ParamsCore } from "./Params.core";
import { SecurityCore } from "./Security.core";

import { ValidationCore } from "./Validation.core";

export class AsyncValidationCore {
  static async asyncIsUrlValid(
    ...args: Parameters<typeof AsyncValidationCore.asyncCheckUrl>
  ): Promise<boolean> {
    const checkUri = await AsyncValidationCore.asyncCheckUrl(...args);
    return checkUri.isValid;
  }

  static async asyncCheckUrl(
    url: string,
    options: AsyncUrlValidationOptions = ValidationCore.defautltValidationOpt,
  ): Promise<AsyncUrlCheckResult> {
    const features: Array<keyof AsyncUrlValidationOptFeature> = [];

    let result: AsyncUrlCheckResult = {
      isValid: true,
      validationDetails: {},
      cause: "",
    };

    result = ValidationCore.checkUrl(url, options);

    if (options.detectMaliciousPatterns) {
      try {
        const maliciousPatternOptions: MaliciousPatternOptions = {
          debug: options.debug,
          sensitivity: options.maliciousPatternSensitivity || 1.0,
          minScore: options.maliciousPatternMinScore || 50,
          ignorePatterns: options.ignoreMaliciousPatternTypes || [],
          customPatterns: options.customMaliciousPatterns || [],
        };

        const maliciousResult = await SecurityCore.analyzeMaliciousPatterns(
          url,
          maliciousPatternOptions,
        );

        result.validationDetails.maliciousPatterns = {
          isValid: !maliciousResult.isMalicious,
          message: maliciousResult.isMalicious
            ? `Malicious patterns detected. Score: ${maliciousResult.score}, Confidence: ${maliciousResult.confidence}`
            : "No malicious patterns detected",
          detectedPatterns: maliciousResult.detectedPatterns,
          score: maliciousResult.score,
          confidence: maliciousResult.confidence,
          recommendation: maliciousResult.recommendation,
        };

        if (maliciousResult.isMalicious) {
          result.isValid = false;
          result.cause = "URL contains malicious patterns";
          return result;
        }
      } catch (error: any) {
        // Log error but don't block the URL if detection fails
        if (options.debug) {
          AppLogger.log(
            `[DEBUG] Error in malicious pattern detection: ${error.message}`,
          );
        }

        result.validationDetails.maliciousPatterns = {
          isValid: true, // Don't fail validation if detection itself fails
          message: `Error in malicious pattern detection: ${error.message}`,
          error: error.message,
        };
      }
    }

    return result;
  }
}
