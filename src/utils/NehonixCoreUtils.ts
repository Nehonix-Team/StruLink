import { AppLogger } from "../common/AppLogger";
import { NehonixSharedUtils } from "../common/StrlCommonUtils";
import {
  AsyncUrlCheckResult,
  AsyncUrlValidationOptFeature,
  AsyncUrlValidationOptions,
  ComparisonRule,
  UrlCheckResult,
  UrlValidationLevel,
  UrlValidationOptions,
  ValidUrlComponents,
} from "../types";
import { MaliciousPatternOptions } from "../services/MaliciousPatterns.service";

import { ValidationCore } from "./coreUtils/Validation.core";
import { AsyncValidationCore } from "./coreUtils/AsyncValidation.core";
import { SecurityCore } from "./coreUtils/Security.core";
import { ParamsCore } from "./coreUtils/Params.core";
import { FormatCore } from "./coreUtils/Format.core";

export class NehonixCoreUtils extends NehonixSharedUtils {

  static checkUrl = ValidationCore.checkUrl;
  static isValidUrl = ValidationCore.isValidUrl;
  static getValidationOptionsByLevel = ValidationCore.getValidationOptionsByLevel;
  
  static asyncIsUrlValid = AsyncValidationCore.asyncIsUrlValid;
  static asyncCheckUrl = AsyncValidationCore.asyncCheckUrl;

  static analyzeMaliciousPatterns = SecurityCore.analyzeMaliciousPatterns;
  static hasMaliciousPatterns = SecurityCore.hasMaliciousPatterns;

  static detectDuplicatedValues = ParamsCore.detectDuplicatedValues;

  static hasBase64Pattern = FormatCore.hasBase64Pattern;
  static hasRawHexString = FormatCore.hasRawHexString;
  static hasJWTFormat = FormatCore.hasJWTFormat;

}

export { NehonixCoreUtils as ncu };
