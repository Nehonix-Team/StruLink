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

export class ValidationCore extends NehonixSharedUtils {
  static defautltValidationOpt: UrlValidationOptions = {
    strictMode: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: true,
    httpsOnly: false,
    maxUrlLength: 2048,
    allowedTLDs: [],
    allowedProtocols: ["http", "https"],
    requireProtocol: false,
    requirePathOrQuery: false,
    strictParamEncoding: false,
    rejectDuplicatedValues: false,
    debug: false,
    allowInternationalChars: false,
    literalValue: "@this",
  };


  static checkUrl(
    url: string,
    options: UrlValidationOptions = this.defautltValidationOpt,
  ): UrlCheckResult {
    // Apply validation level if specified (overrides other options)
    if (options.validationLevel) {
      options = this.getValidationOptionsByLevel(
        options.validationLevel,
        options,
      );
    }

    const result: UrlCheckResult = {
      isValid: true,
      validationDetails: {},
      cause: "",
    };
    AppLogger.debugs_state = options.debug || false;

    // Check if URL is empty
    if (!url.trim()) {
      const message = "URL is empty or contains only whitespace";
      result.cause = message;
      result.validationDetails.emptyCheck = {
        isValid: false,
        message,
      };
      result.isValid = false;
      return result;
    } else {
      result.validationDetails.emptyCheck = {
        isValid: true,
        message: "URL contains valid content",
      };
    }

    // Minimum URL length check
    if (options.minUrlLength && url.length < options.minUrlLength) {
      const message = `URL is too short. Minimum length is ${options.minUrlLength} characters`;
      result.cause = message;
      result.validationDetails.length = {
        isValid: false,
        message,
        actualLength: url.length,
        minLength: options.minUrlLength,
        maxLength: options.maxUrlLength,
      };
      result.isValid = false;
      return result;
    }

    // Maximum URL length check
    if (options.maxUrlLength) {
      if (
        typeof options.maxUrlLength === "number" &&
        options.maxUrlLength > 0 &&
        url.length > options.maxUrlLength
      ) {
        const message = `URL exceeds maximum length of ${options.maxUrlLength} characters`;
        result.cause = message;
        result.validationDetails.length = {
          isValid: false,
          message,
          actualLength: url.length,
          maxLength: options.maxUrlLength,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.length = {
          isValid: true,
          message: `URL length is within the allowed limit of ${options.maxUrlLength} characters`,
          actualLength: url.length,
          maxLength: options.maxUrlLength,
        };
      }
    }

    // Check for disallowed keywords
    if (options.disallowedKeywords && options.disallowedKeywords.length > 0) {
      const lowerUrl = url.toLowerCase();
      const foundKeywords = options.disallowedKeywords.filter((keyword) =>
        lowerUrl.includes(keyword.toLowerCase()),
      );

      if (foundKeywords.length > 0) {
        const message = `URL contains disallowed keywords: ${foundKeywords.join(
          ", ",
        )}`;
        result.cause = message;
        result.validationDetails.disallowedKeywords = {
          isValid: false,
          message,
          foundKeywords,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.disallowedKeywords = {
          isValid: true,
          message: "No disallowed keywords found",
        };
      }
    }

    try {
      // Special handling for data URLs if enabled
      if (url.startsWith("data:") && options.allowDataUrl) {
        const dataUrlPattern =
          /^data:([a-z]+\/[a-z0-9-+.]+)?(;base64)?,([a-z0-9!$&',()*+;=\-._~:@/?%\s]*\s*)$/i;
        if (!dataUrlPattern.test(url)) {
          const message = "Invalid data URL format";
          result.cause = message;
          result.validationDetails.dataUrl = {
            isValid: false,
            message,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.dataUrl = {
            isValid: true,
            message: "Valid data URL format",
          };
          return result; // Skip other checks for data URLs
        }
      } else if (url.startsWith("data:") && !options.allowDataUrl) {
        const message = "Data URLs are not allowed";
        result.cause = message;
        result.validationDetails.dataUrl = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      }

      // Special handling for mailto URLs if enabled
      if (url.startsWith("mailto:") && options.allowMailto) {
        const mailtoPattern =
          /^mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;
        if (!mailtoPattern.test(url)) {
          const message = "Invalid mailto URL format";
          result.cause = message;
          result.validationDetails.mailto = {
            isValid: false,
            message,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.mailto = {
            isValid: true,
            message: "Valid mailto URL format",
          };
          return result; // Skip other checks for mailto URLs
        }
      } else if (url.startsWith("mailto:") && !options.allowMailto) {
        const message = "Mailto URLs are not allowed";
        result.cause = message;
        result.validationDetails.mailto = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      }

      // Handle protocol requirements and validation
      // This checks for a valid protocol pattern like "http://" or "https://"
      const validProtocolPattern = /^[a-z][a-z0-9+.-]*:\/\//i;
      const hasValidProtocol = validProtocolPattern.test(url);

      // This specifically checks for common malformed protocols
      const malformedProtocolPattern =
        /^[a-z][a-z0-9+.-]*:(?!\/{2})|^[a-z][a-z0-9+.-]*\/(?!\/)/i;
      const hasMalformedProtocol = malformedProtocolPattern.test(url);

      // Reject malformed protocols in strict mode
      if (options.strictMode && hasMalformedProtocol) {
        const message =
          "Malformed protocol - must include '://' (e.g. 'https://')";
        result.cause = message;
        result.validationDetails.protocol = {
          isValid: false,
          message,
          allowedProtocols: options.allowedProtocols,
        };
        result.isValid = false;
        return result;
      }

      // Handle protocol requirements
      let parsedUrl = url;

      if (!hasValidProtocol) {
        if (options.requireProtocol) {
          const message =
            "A valid protocol (e.g., 'http://' or 'https://') is required";
          result.cause = message;
          result.validationDetails.protocol = {
            isValid: false,
            message,
            allowedProtocols: options.allowedProtocols,
          };
          result.isValid = false;
          return result;
        }
        parsedUrl = "https://" + url;
      }

      // Parse the URL
      let urlObj: URL | null = null;
      try {
        urlObj = new URL(parsedUrl);
      } catch (error: any) {
        const message = `Failed to parse URL: ${error.message}`;
        result.cause = message;
        result.validationDetails.parsing = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      }

      // Process custom validations
      if (options.customValidations && options.customValidations.length > 0) {
        const validationResults: {
          isValid: boolean;
          message: string;
          rule: ComparisonRule;
        }[] = [];

        // Valid string-returning URL properties
        const validUrlComponents: ValidUrlComponents[] = [
          "href",
          "origin",
          "protocol",
          "username",
          "password",
          "host",
          "hostname",
          "port",
          "pathname",
          "search",
          "hash",
        ];

        for (const [component, operator, value] of options.customValidations) {
          let leftValue: string | number | undefined;
          let isValid = false;
          let message = "";

          // Validate component
          if (component === "literal") {
            if (options.literalValue === undefined) {
              result.cause =
                "'literalValue' option is required when the left value is 'literal'";
              isValid = false;
              message =
                "Literal comparison failed: 'literalValue' option is required";
            } else if (options.literalValue === "@this") {
              leftValue = url;
            } else {
              leftValue = options.literalValue;
            }
          }
          // Add handler for fullCustomValidation components
          else if (
            component.startsWith("fullCustomValidation.") ||
            component.startsWith("fcv.")
          ) {
            const c = component;
            const customKey =
              c.substring("fullCustomValidation.".length) ||
              c.substring("fcv.".length);

            if (
              !options.fullCustomValidation ||
              !(customKey in options.fullCustomValidation)
            ) {
              isValid = false;
              message = `Custom validation failed: Property '${customKey}' not found in fullCustomValidation object`;
            } else {
              leftValue = options.fullCustomValidation[customKey];
            }
          } else if (
            !validUrlComponents.includes(component as ValidUrlComponents)
          ) {
            isValid = false;
            message = `Invalid URL component '${component}'; expected one of: ${validUrlComponents.join(
              ", ",
            )} or a fullCustomValidation property (fullCustomValidation.[key])`;
          } else {
            leftValue = urlObj[component as keyof URL] as string;
          }

          // Perform comparison if leftValue is defined
          if (leftValue !== undefined) {
            switch (operator) {
              case "===":
                isValid = leftValue === value;
                break;
              case "==":
                isValid = leftValue == value;
                break;
              case "!==":
                isValid = leftValue !== value;
                break;
              case "!=":
                isValid = leftValue != value;
                break;
              case "<=":
                isValid = leftValue <= value;
                break;
              case ">=":
                isValid = leftValue >= value;
                break;
              case "<":
                isValid = leftValue < value;
                break;
              case ">":
                isValid = leftValue > value;
                break;
            }
            message = isValid
              ? `Validation passed: ${component} ${operator} ${value}`
              : `Validation failed: ${component} ${operator} ${value} (actual: ${
                  leftValue || "NONE"
                })`;
          }

          // Debug logging
          if (options.debug) {
            AppLogger.log(
              `[DEBUG] Custom Validation: ${component} ${operator} ${value}`,
            );
            AppLogger.log(
              `[DEBUG] Left Value: ${
                leftValue !== undefined ? leftValue : "undefined"
              }`,
            );
            AppLogger.log(`[DEBUG] Result: ${message}`);
          }

          validationResults.push({
            isValid,
            message,
            rule: [component, operator, value],
          });

          if (!isValid) {
            result.isValid = false;
          }
        }

        result.validationDetails.customValidations = {
          isValid: validationResults.every((r) => r.isValid),
          message: validationResults.map((r) => r.message).join("; "),
          results: validationResults,
        };

        if (!result.isValid) {
          result.cause = "One or more custom validations failed";
          return result;
        }
      }

      // Protocol validation
      const protocol = urlObj.protocol.replace(":", "");
      if (options.allowedProtocols) {
        if (
          options.allowedProtocols.length > 0 &&
          !options.allowedProtocols.includes(protocol)
        ) {
          const message = `Invalid protocol detected. Expected one of (${options.allowedProtocols
            .map((p) => `"${p}"`)
            .join(", ")}), but received "${protocol}".`;
          const explanationMessage =
            "The provided protocol is not included in the list of allowed protocols. Please verify your configuration or input URL.";

          result.cause = message;
          result.validationDetails.protocol = {
            isValid: false,
            message: explanationMessage,
            detectedProtocol: protocol,
            allowedProtocols: options.allowedProtocols,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.protocol = {
            isValid: true,
            message: `Protocol '${protocol}' is allowed`,
            detectedProtocol: protocol,
            allowedProtocols: options.allowedProtocols,
          };
        }
      }

      // HTTPS-only validation
      if (options.httpsOnly && protocol !== "https") {
        const message = "Only HTTPS protocol is allowed";
        result.cause = message;
        result.validationDetails.httpsOnly = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.httpsOnly = {
          isValid: true,
          message: options.httpsOnly
            ? "HTTPS protocol is used"
            : "Protocol meets requirements",
        };
      }

      // Secure protocol for non-localhost validation
      if (
        options.requireSecureProtocolForNonLocalhost &&
        urlObj.hostname !== "localhost" &&
        protocol !== "https"
      ) {
        const message = "HTTPS protocol is required for non-localhost domains";
        result.cause = message;
        result.validationDetails.secureNonLocalhost = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.secureNonLocalhost = {
          isValid: true,
          message: "Secure protocol requirements for non-localhost are met",
        };
      }

      // Credentials validation
      if (!options.allowCredentials && (urlObj.username || urlObj.password)) {
        const message = "Username and password in URLs are not allowed";
        result.cause = message;
        result.validationDetails.credentials = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.credentials = {
          isValid: true,
          message: options.allowCredentials
            ? "Credentials are allowed"
            : "No credentials found in URL",
        };
      }

      // URL fragment validation
      if (options.allowFragments === false && urlObj.hash) {
        const message = "URL fragments (hash) are not allowed";
        result.cause = message;
        result.validationDetails.fragments = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.fragments = {
          isValid: true,
          message:
            options.allowFragments === false
              ? "No URL fragments found"
              : "URL fragments are allowed",
        };
      }

      // Domain validation
      const hostParts = urlObj.hostname.split(".");

      // Check allowed domains if specified
      if (options.allowedDomains && options.allowedDomains.length > 0) {
        const isAllowedDomain = options.allowedDomains.some((domain) => {
          // Exact match
          if (urlObj.hostname === domain) return true;
          // Subdomain match if allowed
          if (options.allowSubdomains && urlObj.hostname.endsWith(`.${domain}`))
            return true;
          return false;
        });

        if (!isAllowedDomain) {
          const message = `Domain '${urlObj.hostname}' is not in the allowed domains list`;
          result.cause = message;
          result.validationDetails.allowedDomains = {
            isValid: false,
            message,
            hostname: urlObj.hostname,
            allowedDomains: options.allowedDomains,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.allowedDomains = {
            isValid: true,
            message: `Domain '${urlObj.hostname}' is allowed`,
            hostname: urlObj.hostname,
            allowedDomains: options.allowedDomains,
          };
        }
      }

      // Check for IP address validation
      const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
      const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
      const isIPv4 = ipv4Pattern.test(urlObj.hostname);
      const isIPv6 = ipv6Pattern.test(urlObj.hostname);
      const isIP = isIPv4 || isIPv6;

      if (isIP) {
        if (!options.allowIPAddresses) {
          const message = `IP addresses are not allowed as hostnames: ${urlObj.hostname}`;
          result.cause = message;
          result.validationDetails.ipAddress = {
            isValid: false,
            message,
            hostname: urlObj.hostname,
            isIPv4,
            isIPv6,
          };
          result.isValid = false;
          return result;
        } else if (options.ipv4Only && isIPv6) {
          const message = "Only IPv4 addresses are allowed";
          result.cause = message;
          result.validationDetails.ipAddress = {
            isValid: false,
            message,
            hostname: urlObj.hostname,
            isIPv4,
            isIPv6,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.ipAddress = {
            isValid: true,
            message: `IP address ${urlObj.hostname} is allowed`,
            hostname: urlObj.hostname,
            isIPv4,
            isIPv6,
          };
        }
      }

      // Standard domain validation (skip for IP addresses or localhost)
      if (
        !isIP &&
        !(options.allowLocalhost && urlObj.hostname === "localhost")
      ) {
        if (hostParts.length < 2 || hostParts.some((part) => part === "")) {
          const message = `Invalid hostname '${
            urlObj.hostname
          }'; expected a valid domain${
            options.allowLocalhost ? " or 'localhost'" : ""
          }`;
          result.cause = message;
          result.validationDetails.domain = {
            isValid: false,
            type: "INV_DOMAIN_ERR",
            error: "Invalid domain structure",
            message,
            hostname: urlObj.hostname,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.domain = {
            isValid: true,
            type: "INV_DOMAIN_ERR",
            message: "Domain structure is valid",
            hostname: urlObj.hostname,
          };
        }
      } else if (options.allowLocalhost && urlObj.hostname === "localhost") {
        result.validationDetails.domain = {
          isValid: true,
          type: "INV_DOMAIN_ERR",
          message: "Localhost is valid",
          hostname: urlObj.hostname,
        };
      }

      // TLD validation
      if (options.allowedTLDs && !isIP && urlObj.hostname !== "localhost") {
        if (options.allowedTLDs.length > 0) {
          const tld = hostParts[hostParts.length - 1].toLowerCase();
          if (!options.allowedTLDs.includes(tld)) {
            const message = `TLD '${tld}' is not allowed; expected one of: ${options.allowedTLDs.join(
              ", ",
            )}`;
            result.cause = message;
            result.validationDetails.tld = {
              isValid: false,
              message,
              detectedTld: tld,
              allowedTlds: options.allowedTLDs,
            };
            result.isValid = false;
            return result;
          } else {
            result.validationDetails.tld = {
              isValid: true,
              message: `TLD '${tld}' is allowed`,
              detectedTld: tld,
              allowedTlds: options.allowedTLDs,
            };
          }
        }
      }

      // Path segments validation
      if (options.maxPathSegments) {
        const pathSegments = urlObj.pathname
          .split("/")
          .filter((segment) => segment.length > 0);
        if (pathSegments.length > options.maxPathSegments) {
          const message = `URL contains too many path segments (${pathSegments.length}); maximum allowed is ${options.maxPathSegments}`;
          result.cause = message;
          result.validationDetails.pathSegments = {
            isValid: false,
            message,
            segmentCount: pathSegments.length,
            maxSegments: options.maxPathSegments,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.pathSegments = {
            isValid: true,
            message: `Path segment count (${pathSegments.length}) is within limits`,
            segmentCount: pathSegments.length,
            maxSegments: options.maxPathSegments,
          };
        }
      }

      // Path/query requirement validation
      if (
        options.requirePathOrQuery &&
        urlObj.pathname === "/" &&
        !urlObj.search
      ) {
        const message = "A path or query string is required";
        result.cause = message;
        result.validationDetails.pathOrQuery = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.pathOrQuery = {
          isValid: true,
          message: "Path or query requirements are met",
        };
      }

      // Query parameter count validation
      if (urlObj.search && options.maxQueryParams) {
        const params = urlObj.searchParams;
        const uniqueParamKeys = new Set([...params.keys()]);

        if (uniqueParamKeys.size > options.maxQueryParams) {
          const message = `URL contains too many query parameters (${uniqueParamKeys.size}); maximum allowed is ${options.maxQueryParams}`;
          result.cause = message;
          result.validationDetails.queryParamCount = {
            isValid: false,
            message,
            paramCount: uniqueParamKeys.size,
            maxParams: options.maxQueryParams,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.queryParamCount = {
            isValid: true,
            message: `Query parameter count (${uniqueParamKeys.size}) is within limits`,
            paramCount: uniqueParamKeys.size,
            maxParams: options.maxQueryParams,
          };
        }
      }

      // Empty parameter values validation
      if (options.disallowEmptyParameterValues && urlObj.search) {
        const params = urlObj.searchParams;
        const emptyParams: string[] = [];

        for (const [key, value] of params.entries()) {
          if (value === "") {
            emptyParams.push(key);
          }
        }

        if (emptyParams.length > 0) {
          const message = `URL contains parameters with empty values: ${emptyParams.join(
            ", ",
          )}`;
          result.cause = message;
          result.validationDetails.emptyParams = {
            isValid: false,
            message,
            emptyParams,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.emptyParams = {
            isValid: true,
            message: "No parameters with empty values found",
          };
        }
      }

      // Strict mode path validation
      if (options.strictMode && urlObj.pathname === "/" && urlObj.search) {
        const message =
          "A leading slash is required in the path for strict mode";
        result.cause = message;
        result.validationDetails.strictMode = {
          isValid: false,
          message:
            "In strict mode, a leading slash (e.g., '/path') is required for the path",
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.strictMode = {
          isValid: true,
          message: options.strictMode
            ? "Path meets strict mode requirements"
            : "Strict mode is not enabled",
        };
      }

      // Check for unencoded spaces in query string
      if (urlObj.search.includes(" ")) {
        result.validationDetails.querySpaces = {
          isValid: false,
          message:
            "Query string contains unencoded spaces; encode spaces as '%20'",
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.querySpaces = {
          isValid: true,
          message: "Query string contains no unencoded spaces",
        };
      }

      // Strict parameter encoding validation
      if (options.strictParamEncoding && urlObj.search) {
        const rawQuery = urlObj.search.substring(1);
        const params = rawQuery.split("&");
        const invalidParams: string[] = [];

        for (const param of params) {
          if (param.includes("=")) {
            const [key, value] = param.split("=", 2);
            try {
              const decodedKey = decodeURIComponent(key);
              const reEncodedKey = encodeURIComponent(decodedKey);
              if (key !== reEncodedKey && !key.includes("+")) {
                invalidParams.push(key);
              }
              if (value) {
                const decodedValue = decodeURIComponent(value);
                const reEncodedValue = encodeURIComponent(decodedValue);
                if (value !== reEncodedValue && !value.includes("+")) {
                  invalidParams.push(value);
                }
              }
            } catch {
              invalidParams.push(param);
            }
          }
        }

        if (invalidParams.length > 0) {
          result.validationDetails.paramEncoding = {
            isValid: false,
            message: `Invalid encoding in query parameters: ${invalidParams.join(
              ", ",
            )}`,
            invalidParams,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.paramEncoding = {
            isValid: true,
            message: "Query parameter encoding is valid",
          };
        }
      }

      // Check for duplicate query parameters
      const duplicatedState = ParamsCore.detectDuplicatedValues(urlObj.href);

      if (
        options.rejectDuplicateParams &&
        duplicatedState.duplicatedKeys.length > 0
      ) {
        result.validationDetails.duplicateParams = {
          isValid: false,
          message: `Duplicate query parameter keys detected: ${duplicatedState.duplicatedKeys.join(
            ", ",
          )}`,
          duplicatedKeys: duplicatedState.duplicatedKeys,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.duplicateParams = {
          isValid: true,
          message: options.rejectDuplicateParams
            ? "No duplicate query parameter keys found"
            : "Duplicate keys check is not enabled",
          duplicatedKeys: duplicatedState.duplicatedKeys,
        };
      }

      if (
        options.rejectDuplicatedValues &&
        duplicatedState.duplicatedValues.length > 0
      ) {
        result.validationDetails.duplicateValues = {
          isValid: false,
          message: `Duplicate query parameter values detected: ${duplicatedState.duplicatedValues.join(
            ", ",
          )}`,
          duplicatedValues: duplicatedState.duplicatedValues,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.duplicateValues = {
          isValid: true,
          message: options.rejectDuplicatedValues
            ? "No duplicate query parameter values found"
            : "Duplicate values check is not enabled",
          duplicatedValues: duplicatedState.duplicatedValues,
        };
      }

      // Unicode escape validation
      if (!options.allowUnicodeEscapes && /\\u[\da-f]{4}/i.test(url)) {
        result.validationDetails.unicodeEscapes = {
          isValid: false,
          message: "Unicode escape sequences (e.g., '\\uXXXX') are not allowed",
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.unicodeEscapes = {
          isValid: true,
          message: options.allowUnicodeEscapes
            ? "Unicode escape sequences are allowed"
            : "No unicode escape sequences detected",
        };
      }

      // Parsing success
      result.validationDetails.parsing = {
        isValid: true,
        message: "URL parsed successfully",
      };

      // International character handling
      if (!options.allowInternationalChars) {
        // Check if URL contains non-ASCII characters
        const hasNonAsciiChars = /[^\x00-\x7F]/.test(urlObj.href);
        // Also check if the domain is punycode
        const hasPunycodeDomain = urlObj.hostname.startsWith("xn--");

        if (hasNonAsciiChars || hasPunycodeDomain) {
          result.validationDetails.internationalChars = {
            isValid: false,
            message: "International characters are not allowed",
            containsNonAscii: hasNonAsciiChars,
            containsPunycode: hasPunycodeDomain,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.internationalChars = {
            isValid: true,
            message: "No international characters detected",
          };
        }
      }

      return result;
    } catch (error: any) {
      result.validationDetails.parsing = {
        isValid: false,
        message: `Failed to parse URL: ${error.message}`,
      };
      result.isValid = false;
      return result;
    }
  }

  /**
   * Validates a URL string according to specified options.
   * @param url The URL string to validate
   * @param options Validation options
   * @returns boolean indicating if the URL is valid
   */
  static isValidUrl(
    url: string,
    options: UrlValidationOptions = this.defautltValidationOpt,
  ): boolean {
    const checkUri = this.checkUrl(url, options);
    return checkUri.isValid;
  }

  // New method for setting validation level presets
  static getValidationOptionsByLevel(
    level: UrlValidationLevel,
    baseOptions?: Partial<UrlValidationOptions>,
  ): UrlValidationOptions {
    const defaultOptions = { ...this.defautltValidationOpt };

    switch (level) {
      case "strict":
        return {
          ...defaultOptions,
          ...baseOptions,
          strictMode: true,
          httpsOnly: true,
          requireProtocol: true,
          strictParamEncoding: true,
          rejectDuplicateParams: true,
          rejectDuplicatedValues: true,
          allowUnicodeEscapes: false,
          allowInternationalChars: false,
          allowCredentials: false,
          disallowEmptyParameterValues: true,
          requireSecureProtocolForNonLocalhost: true,
        };
      case "moderate":
        return {
          ...defaultOptions,
          ...baseOptions,
          strictMode: false,
          httpsOnly: true,
          requireProtocol: false,
          strictParamEncoding: true,
          rejectDuplicateParams: true,
          rejectDuplicatedValues: false,
          allowUnicodeEscapes: true,
          allowInternationalChars: true,
          allowCredentials: true,
          disallowEmptyParameterValues: false,
          requireSecureProtocolForNonLocalhost: true,
        };
      case "relaxed":
        return {
          ...defaultOptions,
          ...baseOptions,
          strictMode: false,
          httpsOnly: false,
          requireProtocol: false,
          strictParamEncoding: false,
          rejectDuplicateParams: false,
          rejectDuplicatedValues: false,
          allowUnicodeEscapes: true,
          allowInternationalChars: true,
          allowCredentials: true,
          allowIPAddresses: true,
          allowLocalhost: true,
          disallowEmptyParameterValues: false,
          requireSecureProtocolForNonLocalhost: false,
        };
      default:
        return { ...defaultOptions, ...baseOptions };
    }
  }
}
