export class ParamsCore {
  static detectDuplicatedValues(url: string): {
    duplicatedKeys: string[];
    duplicatedValues: string[];
    params: Record<string, string[]>;
  } {
    try {
      const urlObj = new URL(url);
      const queryString = urlObj.search.substring(1);

      if (!queryString) {
        return { duplicatedKeys: [], duplicatedValues: [], params: {} };
      }

      const params: Record<string, string[]> = {};
      const paramPairs = queryString.split("&");
      const duplicatedKeys: string[] = [];
      const duplicatedValues: string[] = [];
      const seenValues = new Set<string>();

      for (const pair of paramPairs) {
        if (!pair) continue;

        const [key, value] = pair.split("=").map((p) => decodeURIComponent(p));

        if (!params[key]) {
          params[key] = [];
        }

        // Check for duplicated keys
        if (params[key].length > 0 && !duplicatedKeys.includes(key)) {
          duplicatedKeys.push(key);
        }

        // Check for duplicated values
        if (value !== undefined) {
          if (seenValues.has(value) && !duplicatedValues.includes(value)) {
            duplicatedValues.push(value);
          }
          seenValues.add(value);
          params[key].push(value);
        } else {
          params[key].push("");
        }
      }

      return { duplicatedKeys, duplicatedValues, params };
    } catch (error) {
      return { duplicatedKeys: [], duplicatedValues: [], params: {} };
    }
  }
}
