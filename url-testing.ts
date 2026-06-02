import { __strl__, MaliciousPatternType } from "./src/index";

// ─────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────
interface TestCase {
  url: string;
  label: string;
  expectedMalicious: boolean;
  category: string;
  note?: string;
}

interface TestResult {
  label: string;
  url: string;
  category: string;
  expectedMalicious: boolean;
  gotMalicious: boolean;
  passed: boolean;
  isFalsePositive: boolean;
  isFalseNegative: boolean;
  score: number;
  confidence: string;
  patterns: string[];
  note?: string;
}

// ─────────────────────────────────────────────
//  Test Cases
// ─────────────────────────────────────────────
const testCases: TestCase[] = [
  // ══════════════════════════════════════════
  // 1. URLS LÉGITIMES — Express / APIs REST
  // ══════════════════════════════════════════
  {
    label: "Root path",
    url: "http://localhost:3000/",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "Simple API route",
    url: "http://localhost:3000/api/users",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "REST resource with ID",
    url: "http://localhost:3000/api/users/42",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "Nested REST route",
    url: "https://api.example.com/v1/organizations/99/members/7/roles",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "Query string - filters",
    url: "https://api.example.com/products?category=electronics&price_min=10&price_max=500",
    expectedMalicious: false,
    category: "Legitimate - Query strings",
  },
  {
    label: "Query string - pagination",
    url: "https://api.example.com/posts?page=2&limit=20&sort=created_at&order=desc",
    expectedMalicious: false,
    category: "Legitimate - Query strings",
  },
  {
    label: "Query string - search term with spaces encoded",
    url: "https://shop.example.com/search?q=blue+running+shoes&size=42",
    expectedMalicious: false,
    category: "Legitimate - Query strings",
  },
  {
    label: "Query string - UUID param",
    url: "https://api.example.com/sessions?token=550e8400-e29b-41d4-a716-446655440000",
    expectedMalicious: false,
    category: "Legitimate - Query strings",
  },
  {
    label: "URL with port",
    url: "http://localhost:8080/health",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "HTTPS production URL",
    url: "https://dashboard.stripe.com/payments/overview",
    expectedMalicious: false,
    category: "Legitimate - Production",
  },
  {
    label: "URL with hash fragment",
    url: "https://docs.example.com/guide/setup#installation",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "File extension route",
    url: "https://cdn.example.com/assets/logo.png",
    expectedMalicious: false,
    category: "Legitimate - Static assets",
  },
  {
    label: "Encoded accents in path (legitimate i18n)",
    url: "https://example.fr/produits/caf%C3%A9",
    expectedMalicious: false,
    category: "Legitimate - Encoding",
    note: "Accented chars encoded correctly",
  },
  {
    label: "Kebab-case route with numbers",
    url: "https://api.example.com/order-items/item-123/confirm",
    expectedMalicious: false,
    category: "Legitimate - Basic",
  },
  {
    label: "Webhook callback URL",
    url: "https://myapp.com/webhooks/stripe?event=payment_intent.succeeded",
    expectedMalicious: false,
    category: "Legitimate - Query strings",
  },
  {
    label: "OAuth redirect URI",
    url: "https://myapp.com/auth/callback?code=abc123&state=xyz789",
    expectedMalicious: false,
    category: "Legitimate - Auth",
  },
  {
    label: "Long but clean data URL",
    url: "https://api.example.com/reports?from=2024-01-01&to=2024-12-31&format=json&include_archived=true&group_by=month",
    expectedMalicious: false,
    category: "Legitimate - Query strings",
  },
  {
    label: "API key as query param (common pattern)",
    url: "https://maps.googleapis.com/maps/api/geocode/json?address=Paris&key=AIzaSyDEMOKEY",
    expectedMalicious: false,
    category: "Legitimate - Auth",
  },
  {
    label: "URL with underscores and dots",
    url: "https://cdn.my_company.io/static/v2.3.1/bundle.min.js",
    expectedMalicious: false,
    category: "Legitimate - Static assets",
  },

  // ══════════════════════════════════════════
  // 2. FAUX POSITIFS POTENTIELS — Edge cases dev
  // ══════════════════════════════════════════
  {
    label: "Template param name containing 'script' word",
    url: "https://api.example.com/transcript/42",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "substring 'script' in legit word 'transcript'",
  },
  {
    label: "Route named 'execute'",
    url: "https://api.example.com/execute-task/run",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "exec-like word in route",
  },
  {
    label: "Query param 'select'",
    url: "https://api.example.com/data?select=id,name,email",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "SQL keyword as legit GraphQL/REST field selector",
  },
  {
    label: "Query param 'union' (Hasura-style)",
    url: "https://api.example.com/graphql?operationName=UnionType",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "SQL keyword in legitimate GraphQL operation name",
  },
  {
    label: "Base64 encoded JSON in query param",
    url: "https://api.example.com/data?filter=eyJuYW1lIjoiSm9obiJ9",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "Legit base64 state param, common in SPAs",
  },
  {
    label: "JWT token in query string",
    url: "https://api.example.com/verify?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "JWT passthrough is standard in some APIs",
  },
  {
    label: "URL with 'eval' substring in legit word",
    url: "https://api.example.com/evaluation/results",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "substr 'eval' inside 'evaluation'",
  },
  {
    label: "URL with 'drop' in route name",
    url: "https://api.example.com/dropbox/upload",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "SQL DROP keyword in legitimate product name",
  },
  {
    label: "URL with 'insert' as route",
    url: "https://api.example.com/insert-record",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "SQL keyword as REST verb in route",
  },
  {
    label: "Markdown-like content in query param",
    url: "https://example.com/preview?content=Hello+**world**+and+_italic_",
    expectedMalicious: false,
    category: "False Positive Risk",
  },
  {
    label: "URL with double slash in path (CDN common pattern)",
    url: "https://cdn.example.com//v2//assets/file.js",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "Double slashes — path traversal false positive risk",
  },
  {
    label: "Localhost with long query string",
    url: "http://localhost:4000/api/debug?verbose=true&trace=all&format=pretty",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "Dev debugging params",
  },
  {
    label: "URL with percent-encoded parentheses (legitimate)",
    url: "https://example.com/docs/function%28arg%29",
    expectedMalicious: false,
    category: "False Positive Risk",
  },
  {
    label: "Query param named 'callback' (JSONP legacy)",
    url: "https://api.example.com/data?callback=myHandler",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "JSONP pattern — not malicious by itself",
  },
  {
    label: "Path with 'admin' segment",
    url: "https://myapp.com/admin/dashboard",
    expectedMalicious: false,
    category: "False Positive Risk",
    note: "Admin routes are legitimate",
  },

  // ══════════════════════════════════════════
  // 3. XSS — Cross-Site Scripting
  // ══════════════════════════════════════════
  {
    label: "XSS: basic script tag in path",
    url: "http://localhost:8085/rc/handler/<script>alert(document.cookie)</script>",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: script tag in query param",
    url: "https://example.com/search?q=<script>alert('xss')</script>",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: img onerror",
    url: "https://example.com/page?msg=<img src=x onerror=alert(1)>",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: javascript: protocol",
    url: "https://example.com/redirect?to=javascript:alert(document.domain)",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: URL-encoded script tag",
    url: "https://example.com/page?input=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: double URL-encoded",
    url: "https://example.com/page?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: SVG with onload",
    url: "https://example.com/upload?file=<svg onload=alert(1)>",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: iframe injection",
    url: "https://example.com/content?html=<iframe src='http://evil.com'></iframe>",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: event handler on div",
    url: "https://example.com/msg?text=<div onmouseover=alert(1)>hover</div>",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: HTML entity bypass",
    url: "https://example.com/page?q=&lt;script&gt;alert(1)&lt;/script&gt;",
    expectedMalicious: true,
    category: "XSS",
  },
  {
    label: "XSS: data URI with script",
    url: "https://example.com/redirect?to=data:text/html,<script>alert(1)</script>",
    expectedMalicious: true,
    category: "XSS",
  },

  // ══════════════════════════════════════════
  // 4. SQL Injection
  // ══════════════════════════════════════════
  {
    label: "SQLi: classic OR 1=1",
    url: "https://example.com/login?user=admin'--&pass=anything",
    expectedMalicious: true,
    category: "SQL Injection",
  },
  {
    label: "SQLi: UNION SELECT",
    url: "https://example.com/items?id=1 UNION SELECT username,password FROM users--",
    expectedMalicious: true,
    category: "SQL Injection",
  },
  {
    label: "SQLi: tautology",
    url: "https://example.com/products?id=1' OR '1'='1",
    expectedMalicious: true,
    category: "SQL Injection",
  },
  {
    label: "SQLi: stacked queries",
    url: "https://example.com/page?id=1; DROP TABLE users;--",
    expectedMalicious: true,
    category: "SQL Injection",
  },
  {
    label: "SQLi: blind - time based",
    url: "https://example.com/api?id=1' AND SLEEP(5)--",
    expectedMalicious: true,
    category: "SQL Injection",
  },
  {
    label: "SQLi: error-based with EXTRACTVALUE",
    url: "https://example.com/data?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))",
    expectedMalicious: true,
    category: "SQL Injection",
  },
  {
    label: "SQLi: encoded quote",
    url: "https://example.com/search?q=test%27%20OR%20%271%27%3D%271",
    expectedMalicious: true,
    category: "SQL Injection",
  },

  // ══════════════════════════════════════════
  // 5. Path Traversal / LFI
  // ══════════════════════════════════════════
  {
    label: "LFI: basic ../etc/passwd",
    url: "https://example.com/download?file=../../../../etc/passwd",
    expectedMalicious: true,
    category: "Path Traversal",
  },
  {
    label: "LFI: URL-encoded dot-dot-slash",
    url: "https://example.com/files?path=..%2F..%2F..%2Fetc%2Fpasswd",
    expectedMalicious: true,
    category: "Path Traversal",
  },
  {
    label: "LFI: double-encoded traversal",
    url: "https://example.com/file?name=..%252F..%252Fetc%252Fshadow",
    expectedMalicious: true,
    category: "Path Traversal",
  },
  {
    label: "LFI: Windows path traversal",
    url: "https://example.com/read?path=..\\..\\Windows\\system32\\drivers\\etc\\hosts",
    expectedMalicious: true,
    category: "Path Traversal",
  },
  {
    label: "LFI: null byte injection",
    url: "https://example.com/include?page=../../../../etc/passwd%00",
    expectedMalicious: true,
    category: "Path Traversal",
  },

  // ══════════════════════════════════════════
  // 6. Open Redirect
  // ══════════════════════════════════════════
  {
    label: "Open Redirect: external URL",
    url: "https://legit.com/redirect?url=https://evil.com/phishing",
    expectedMalicious: true,
    category: "Open Redirect",
  },
  {
    label: "Open Redirect: protocol-relative",
    url: "https://legit.com/login?next=//evil.com",
    expectedMalicious: true,
    category: "Open Redirect",
  },
  {
    label: "Open Redirect: URL-encoded",
    url: "https://legit.com/go?to=https%3A%2F%2Fevil.com",
    expectedMalicious: true,
    category: "Open Redirect",
  },

  // ══════════════════════════════════════════
  // 7. SSRF — Server-Side Request Forgery
  // ══════════════════════════════════════════
  {
    label: "SSRF: internal IP 169.254 (metadata AWS)",
    url: "https://api.example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
    expectedMalicious: true,
    category: "SSRF",
  },
  {
    label: "SSRF: localhost fetch",
    url: "https://api.example.com/proxy?target=http://localhost:6379",
    expectedMalicious: true,
    category: "SSRF",
  },
  {
    label: "SSRF: 0.0.0.0",
    url: "https://api.example.com/webhook?callback=http://0.0.0.0:22",
    expectedMalicious: true,
    category: "SSRF",
  },
  {
    label: "SSRF: internal subnet 192.168.x.x",
    url: "https://api.example.com/proxy?url=http://192.168.1.1/admin",
    expectedMalicious: true,
    category: "SSRF",
  },
  {
    label: "SSRF: DNS rebinding via decimal IP",
    url: "https://api.example.com/img?src=http://2130706433/secret", // 127.0.0.1 decimal
    expectedMalicious: true,
    category: "SSRF",
    note: "2130706433 = 127.0.0.1 in decimal",
  },
  {
    label: "SSRF: file:// protocol",
    url: "https://api.example.com/render?source=file:///etc/passwd",
    expectedMalicious: true,
    category: "SSRF",
  },

  // ══════════════════════════════════════════
  // 8. Command Injection
  // ══════════════════════════════════════════
  {
    label: "CMDi: pipe shell command",
    url: "https://example.com/ping?host=8.8.8.8|cat /etc/passwd",
    expectedMalicious: true,
    category: "Command Injection",
  },
  {
    label: "CMDi: backtick execution",
    url: "https://example.com/lookup?domain=`id`",
    expectedMalicious: true,
    category: "Command Injection",
  },
  {
    label: "CMDi: semicolon chaining",
    url: "https://example.com/host?ip=127.0.0.1;rm -rf /",
    expectedMalicious: true,
    category: "Command Injection",
  },
  {
    label: "CMDi: $() subshell",
    url: "https://example.com/exec?cmd=$(whoami)",
    expectedMalicious: true,
    category: "Command Injection",
  },

  // ══════════════════════════════════════════
  // 9. Template Injection (SSTI)
  // ══════════════════════════════════════════
  {
    label: "SSTI: Jinja2 basic",
    url: "https://example.com/greet?name={{7*7}}",
    expectedMalicious: true,
    category: "Template Injection",
  },
  {
    label: "SSTI: Jinja2 config leak",
    url: "https://example.com/render?tpl={{config}}",
    expectedMalicious: true,
    category: "Template Injection",
  },
  {
    label: "SSTI: Handlebars",
    url: "https://example.com/page?template={{this.constructor.name}}",
    expectedMalicious: true,
    category: "Template Injection",
  },
  {
    label: "SSTI: ERB Ruby",
    url: "https://example.com/profile?name=<%= 7*7 %>",
    expectedMalicious: true,
    category: "Template Injection",
  },

  // ══════════════════════════════════════════
  // 10. Protocol-based attacks
  // ══════════════════════════════════════════
  {
    label: "Protocol: vbscript:",
    url: "https://example.com/link?href=vbscript:msgbox(1)",
    expectedMalicious: true,
    category: "Protocol Attack",
  },
  {
    label: "Protocol: data:text/html",
    url: "https://example.com/preview?src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    expectedMalicious: true,
    category: "Protocol Attack",
    note: "base64 of <script>alert(1)</script>",
  },
  {
    label: "Protocol: javascript uppercase bypass",
    url: "https://example.com/go?url=JAVASCRIPT:alert(1)",
    expectedMalicious: true,
    category: "Protocol Attack",
  },

  // ══════════════════════════════════════════
  // 11. Header injection / CRLF
  // ══════════════════════════════════════════
  {
    label: "CRLF injection",
    url: "https://example.com/redirect?url=https://example.com%0d%0aSet-Cookie:+session=hacked",
    expectedMalicious: true,
    category: "CRLF Injection",
  },
  {
    label: "CRLF with newline chars",
    url: "https://example.com/page?input=value%0AX-Injected-Header: evil",
    expectedMalicious: true,
    category: "CRLF Injection",
  },

  // ══════════════════════════════════════════
  // 12. Advanced/Obfuscated Attacks
  // ══════════════════════════════════════════
  {
    label: "Obfuscated XSS: Unicode escapes",
    url: "https://example.com/page?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    expectedMalicious: true,
    category: "Obfuscated",
  },
  {
    label: "Obfuscated XSS: mixed case",
    url: "https://example.com/page?q=<ScRiPt>alert(1)</sCrIpT>",
    expectedMalicious: true,
    category: "Obfuscated",
  },
  {
    label: "Polyglot XSS",
    url: "https://example.com/page?q=javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
    expectedMalicious: true,
    category: "Obfuscated",
  },
  {
    label: "Double encoding SQLi",
    url: "https://example.com/user?id=1%2527%2520OR%25201%253D1",
    expectedMalicious: true,
    category: "Obfuscated",
  },
];

// ─────────────────────────────────────────────
//  Runner
// ─────────────────────────────────────────────
const results: TestResult[] = [];
const errors: { label: string; error: string }[] = [];

console.log(`\n${"═".repeat(60)}`);
console.log("  🔍 StruLink URL Security — Stress Test Suite");
console.log(`${"═".repeat(60)}\n`);
console.log(`Running ${testCases.length} test cases...\n`);

for (const tc of testCases) {
  try {
    const result = await __strl__.scanUrl(tc.url, {});

    const gotMalicious = result.isMalicious;
    const passed = gotMalicious === tc.expectedMalicious;
    const isFalsePositive = !tc.expectedMalicious && gotMalicious;
    const isFalseNegative = tc.expectedMalicious && !gotMalicious;

    const r: TestResult = {
      label: tc.label,
      url: tc.url,
      category: tc.category,
      expectedMalicious: tc.expectedMalicious,
      gotMalicious,
      passed,
      isFalsePositive,
      isFalseNegative,
      score: result.score ?? 0,
      confidence: result.confidence ?? "unknown",
      patterns: (result.detectedPatterns ?? []).map((p: any) => p.type),
      note: tc.note,
    };

    results.push(r);

    const icon = passed ? "✅" : isFalsePositive ? "🟡 FP" : "🔴 FN";
    console.log(`${icon} [${tc.category}] ${tc.label}`);
    if (!passed) {
      console.log(`     URL: ${tc.url.substring(0, 80)}...`);
      console.log(
        `     Expected: ${tc.expectedMalicious} | Got: ${gotMalicious} | Score: ${r.score} | Patterns: ${r.patterns.join(", ") || "none"}`,
      );
      if (tc.note) console.log(`     Note: ${tc.note}`);
    }
  } catch (e: any) {
    errors.push({ label: tc.label, error: e?.message ?? String(e) });
    console.log(`💥 ERROR [${tc.category}] ${tc.label}: ${e?.message}`);
  }
}

// ─────────────────────────────────────────────
//  Summary Stats
// ─────────────────────────────────────────────
const total = results.length;
const passed = results.filter((r) => r.passed).length;
const falsePositives = results.filter((r) => r.isFalsePositive);
const falseNegatives = results.filter((r) => r.isFalseNegative);
const byCategory = new Map<
  string,
  { total: number; passed: number; fp: number; fn: number }
>();

for (const r of results) {
  if (!byCategory.has(r.category))
    byCategory.set(r.category, { total: 0, passed: 0, fp: 0, fn: 0 });
  const c = byCategory.get(r.category)!;
  c.total++;
  if (r.passed) c.passed++;
  if (r.isFalsePositive) c.fp++;
  if (r.isFalseNegative) c.fn++;
}

console.log(`\n${"═".repeat(60)}`);
console.log("  📊 RESULTS SUMMARY");
console.log(`${"═".repeat(60)}`);
console.log(`Total:          ${total}`);
console.log(
  `✅ Passed:       ${passed} (${((passed / total) * 100).toFixed(1)}%)`,
);
console.log(`🟡 False Pos:   ${falsePositives.length}`);
console.log(`🔴 False Neg:   ${falseNegatives.length}`);
console.log(`💥 Errors:       ${errors.length}`);

console.log(`\n── By Category ${"─".repeat(44)}`);
for (const [cat, stats] of [...byCategory.entries()].sort()) {
  const pct = ((stats.passed / stats.total) * 100).toFixed(0);
  const fp = stats.fp > 0 ? ` 🟡${stats.fp}FP` : "";
  const fn = stats.fn > 0 ? ` 🔴${stats.fn}FN` : "";
  console.log(
    `  ${cat.padEnd(32)} ${stats.passed}/${stats.total} (${pct}%)${fp}${fn}`,
  );
}

// ─────────────────────────────────────────────
//  Export raw JSON for the report generator
// ─────────────────────────────────────────────
const exportData = {
  timestamp: new Date().toISOString(),
  total,
  passed,
  falsePositives: falsePositives.map((r) => ({
    label: r.label,
    url: r.url,
    score: r.score,
    patterns: r.patterns,
    note: r.note,
  })),
  falseNegatives: falseNegatives.map((r) => ({
    label: r.label,
    url: r.url,
    score: r.score,
    note: r.note,
  })),
  errors,
  byCategory: Object.fromEntries(byCategory),
  allResults: results,
};

await Bun.write("test-results.json", JSON.stringify(exportData, null, 2));
console.log(`\n💾 Résultats bruts sauvegardés dans test-results.json`);
console.log(`   Lance ensuite: bun report-generator.ts\n`);
