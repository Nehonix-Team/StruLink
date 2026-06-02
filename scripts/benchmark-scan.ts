import { StruLink } from "../src/StruLink";
import fs from "fs";

async function main() {
  const args = process.argv.slice(2);
  let count = 1000;
  let baseUrl = "https://example.com/resource";

  for (const a of args) {
    if (a.startsWith("--count=")) {
      count = Math.max(1, Number(a.split("=")[1]) || 1000);
    }
    if (a.startsWith("--url=")) {
      baseUrl = a.split("=")[1] || baseUrl;
    }
    if (a === "--single") {
      count = 1;
    }
  }

  console.log(`Benchmark: scanning ${count} URL(s) using base '${baseUrl}'`);

  const results: Array<{ url: string; timeMs: number; error?: string }> = [];
  const tStart = Date.now();

  for (let i = 0; i < count; i++) {
    const url = baseUrl.includes("?")
      ? `${baseUrl}&_b=${i}`
      : `${baseUrl}?_b=${i}`;
    const s = Date.now();
    try {
      await StruLink.scanUrl(url, { debug: false });
      const e = Date.now();
      results.push({ url, timeMs: e - s });
      if (i % 100 === 0) console.log(`scanned ${i}...`);
    } catch (err: any) {
      const e = Date.now();
      results.push({ url, timeMs: e - s, error: String(err) });
    }
  }

  const tEnd = Date.now();
  const totalMs = tEnd - tStart;
  const avgMs = results.reduce((a, b) => a + b.timeMs, 0) / results.length;

  const output = {
    count: results.length,
    totalMs,
    avgMs,
    sample: results.slice(0, Math.min(25, results.length)),
    timestamp: new Date().toISOString(),
  };

  fs.writeFileSync("benchmark-results.json", JSON.stringify(output, null, 2));
  console.log("Benchmark complete:", JSON.stringify(output, null, 2));
}

main().catch((e) => {
  console.error("Benchmark script error:", e);
  process.exit(1);
});
