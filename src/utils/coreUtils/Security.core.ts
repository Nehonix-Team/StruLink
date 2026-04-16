import { MaliciousPatternOptions } from "../../services/MaliciousPatterns.service";
import NSS from "../../services/StruSecurity.service";

export class SecurityCore {
  /**
   * Analyzes a URL for potential security threats
   * @param url The URL to analyze
   * @param options Detection options
   * @returns Detailed analysis of security threats
   */
  static analyzeMaliciousPatterns(
    url: string,
    options: MaliciousPatternOptions = {},
  ) {
    const maliciousResult = NSS.analyzeUrl(url, options);
    return maliciousResult;
  }

  /**
   * Quick check if a URL contains malicious patterns
   * @param url The URL to check
   * @param options Detection options
   * @returns Boolean indicating if URL contains malicious patterns
   */
  static async hasMaliciousPatterns(
    url: string,
    options: MaliciousPatternOptions = {},
  ): Promise<boolean> {
    const x = await SecurityCore.analyzeMaliciousPatterns(url, options);
    return x.isMalicious;
  }
}
