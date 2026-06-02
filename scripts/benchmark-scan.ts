import { StruLink } from "../src/StruLink";
import fs from "fs";

async function main() {
  const args = process.argv.slice(2);
  let count = 1000;
  let baseUrl = "https://example.com/resource";
  let concurrency = 1; // 1 = séquentiel (par défaut)
  let skipWarmup = false;

  // Parsing des arguments
  for (const a of args) {
    if (a.startsWith("--count=")) {
      count = Math.max(1, Number(a.split("=")[1]) || 1000);
    }
    if (a.startsWith("--url=")) {
      baseUrl = a.split("=")[1] || baseUrl;
    }
    if (a.startsWith("--concurrency=")) {
      concurrency = Math.max(1, Number(a.split("=")[1]) || 1);
    }
    if (a === "--single") {
      count = 1;
    }
    if (a === "--skip-warmup") {
      skipWarmup = true;
    }
  }

  // 1. Phase de Warm-up (Échauffement)
  if (!skipWarmup && count > 10) {
    console.log("🔥 Phase de warm-up en cours (15 requêtes à blanc)...");
    for (let i = 0; i < 15; i++) {
      try {
        await StruLink.scanUrl(`${baseUrl}?_warmup=${i}`, { debug: false });
      } catch {
        // On ignore les erreurs de warm-up pour ne pas bloquer le bench
      }
    }
    console.log(
      "✅ Code optimisé par le JIT. Lancement du benchmark officiel...\n",
    );
  }

  console.log(
    `Benchmark: scanning ${count} URL(s) [Concurrency: ${concurrency}] using base '${baseUrl}'`,
  );

  const results: Array<{ url: string; timeMs: number; error?: string }> = [];
  const tStart = Date.now();

  // Fonction utilitaire pour formater l'URL
  const getUrl = (index: number) => {
    return baseUrl.includes("?")
      ? `${baseUrl}&_b=${index}`
      : `${baseUrl}?_b=${index}`;
  };

  // 2. Gestion de l'exécution (Concurrente vs Séquentielle)
  if (concurrency > 1) {
    // Mode Concurrence (par paquets / batches de taille 'concurrency')
    for (let i = 0; i < count; i += concurrency) {
      const batchPromises = [];
      const currentBatchSize = Math.min(concurrency, count - i);

      for (let j = 0; j < currentBatchSize; j++) {
        const index = i + j;
        const url = getUrl(index);

        const runTask = async () => {
          const s = Date.now();
          try {
            await StruLink.scanUrl(url, { debug: false });
            results.push({ url, timeMs: Date.now() - s });
          } catch (err: any) {
            results.push({ url, timeMs: Date.now() - s, error: String(err) });
          }
        };
        batchPromises.push(runTask());
      }

      await Promise.all(batchPromises);
      if (i % 100 === 0 || i + currentBatchSize >= count) {
        console.log(
          `scanned ${Math.min(i + currentBatchSize, count)}/${count}...`,
        );
      }
    }
  } else {
    // Mode Séquentiel classique
    for (let i = 0; i < count; i++) {
      const url = getUrl(i);
      const s = Date.now();
      try {
        await StruLink.scanUrl(url, { debug: false });
        results.push({ url, timeMs: Date.now() - s });
        if (i % 100 === 0) console.log(`scanned ${i}...`);
      } catch (err: any) {
        results.push({ url, timeMs: Date.now() - s, error: String(err) });
      }
    }
  }

  const tEnd = Date.now();
  const totalMs = tEnd - tStart;
  const avgMs = results.reduce((a, b) => a + b.timeMs, 0) / results.length;

  const output = {
    count: results.length,
    concurrency,
    totalMs,
    avgMs: Number(avgMs.toFixed(2)),
    sample: results.slice(0, Math.min(25, results.length)),
    timestamp: new Date().toISOString(),
  };

  fs.writeFileSync("benchmark-results.json", JSON.stringify(output, null, 2));
  console.log("\nBenchmark complete:", JSON.stringify(output, null, 2));
}

main().catch((e) => {
  console.error("Benchmark script error:", e);
  process.exit(1);
});
