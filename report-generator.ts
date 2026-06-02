import { readFileSync } from "fs";

const raw = readFileSync("test-results.json", "utf-8");
const data = JSON.parse(raw);

const {
  timestamp,
  total,
  passed,
  falsePositives,
  falseNegatives,
  errors,
  byCategory,
  allResults,
} = data;

const failRate = (((total - passed) / total) * 100).toFixed(1);
const passRate = ((passed / total) * 100).toFixed(1);
const fpCount = falsePositives.length;
const fnCount = falseNegatives.length;
const date = new Date(timestamp).toLocaleString("fr-FR");

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
function badge(val: number, warn = 1, bad = 3) {
  if (val === 0) return "🟢";
  if (val <= warn) return "🟡";
  return "🔴";
}

function truncate(s: string, n = 90) {
  return s.length > n ? s.substring(0, n) + "…" : s;
}

function categoryTable() {
  const rows = Object.entries(byCategory)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([cat, stats]: [string, any]) => {
      const pct = ((stats.passed / stats.total) * 100).toFixed(0);
      const fp = stats.fp > 0 ? `${stats.fp} ⚠️` : "—";
      const fn = stats.fn > 0 ? `${stats.fn} 🚨` : "—";
      const icon =
        stats.fp + stats.fn === 0 ? "✅" : stats.fp > 0 ? "🟡" : "🔴";
      return `| ${icon} | ${cat} | ${stats.passed}/${stats.total} | ${pct}% | ${fp} | ${fn} |`;
    });

  return [
    "| | Catégorie | Résultat | Taux | Faux Positifs | Faux Négatifs |",
    "|---|---|---|---|---|---|",
    ...rows,
  ].join("\n");
}

// ─────────────────────────────────────────────
// Recommandations automatiques
// ─────────────────────────────────────────────
interface Reco {
  priority: "CRITIQUE" | "HAUTE" | "MOYENNE" | "INFO";
  title: string;
  detail: string;
}

function generateRecos(): Reco[] {
  const recos: Reco[] = [];

  // Faux négatifs par catégorie
  const fnByCategory: Record<string, string[]> = {};
  for (const r of allResults) {
    if (r.isFalseNegative) {
      if (!fnByCategory[r.category]) fnByCategory[r.category] = [];
      fnByCategory[r.category].push(r.label);
    }
  }

  for (const [cat, cases] of Object.entries(fnByCategory)) {
    const priority =
      cat === "XSS" || cat === "SQL Injection" || cat === "Command Injection"
        ? "CRITIQUE"
        : "HAUTE";
    recos.push({
      priority,
      title: `Faux négatifs détectés — ${cat}`,
      detail: `${cases.length} cas non détectés : ${cases.slice(0, 3).join(", ")}${cases.length > 3 ? `, +${cases.length - 3} autres` : ""}. Renforcer les patterns de détection pour cette catégorie.`,
    });
  }

  // Faux positifs
  const fpByCategory: Record<string, string[]> = {};
  for (const r of allResults) {
    if (r.isFalsePositive) {
      if (!fpByCategory[r.category]) fpByCategory[r.category] = [];
      fpByCategory[r.category].push(r.label);
    }
  }

  for (const [cat, cases] of Object.entries(fpByCategory)) {
    recos.push({
      priority: "HAUTE",
      title: `Faux positifs — ${cat}`,
      detail: `${cases.length} URL légitimes bloquées à tort : ${cases.slice(0, 3).join(", ")}. Affiner les regex pour éviter les collisions sur des sous-chaînes (ex: "transcript" vs "script", "evaluation" vs "eval").`,
    });
  }

  // Checks spécifiques
  const ssrfFn = allResults.filter(
    (r: any) => r.category === "SSRF" && r.isFalseNegative,
  );
  if (ssrfFn.length > 0) {
    recos.push({
      priority: "CRITIQUE",
      title: "SSRF — IPs internes non détectées",
      detail:
        "Des IPs en notation décimale (ex: 2130706433 = 127.0.0.1) ou des plages de métadonnées cloud (169.254.x.x) ne sont pas interceptées. Implémenter une résolution d'IP canonique avant validation.",
    });
  }

  const obfusFn = allResults.filter(
    (r: any) => r.category === "Obfuscated" && r.isFalseNegative,
  );
  if (obfusFn.length > 0) {
    recos.push({
      priority: "CRITIQUE",
      title: "Contournements par obfuscation non détectés",
      detail: `${obfusFn.length} cas obfusqués passent sans alerte. Ajouter une étape de normalisation multi-passes (Unicode unescape, HTML entity decode, double URL decode) AVANT le scan des patterns.`,
    });
  }

  const crlfFn = allResults.filter(
    (r: any) => r.category === "CRLF Injection" && r.isFalseNegative,
  );
  if (crlfFn.length > 0) {
    recos.push({
      priority: "HAUTE",
      title: "CRLF Injection non détectée",
      detail:
        "Les séquences \\r\\n encodées (%0d%0a) dans les paramètres ne sont pas détectées. Ajouter un pattern couvrant les sauts de ligne URL-encodés.",
    });
  }

  // Bonne perf
  if (fpCount === 0) {
    recos.push({
      priority: "INFO",
      title: "Aucun faux positif — Express safe ✅",
      detail:
        "Toutes les URLs légitimes (routes Express, JWT, OAuth, base64, mots-clés SQL dans des noms légitimes) ont passé sans fausse alarme. L'expérience développeur ne sera pas impactée.",
    });
  }

  if (errors.length > 0) {
    recos.push({
      priority: "HAUTE",
      title: `${errors.length} erreur(s) d'exécution pendant les tests`,
      detail: `Certains appels à scanUrl ont levé des exceptions. Vérifier la robustesse sur les URLs malformées ou contenant des caractères spéciaux non gérés.`,
    });
  }

  const priorityOrder = { CRITIQUE: 0, HAUTE: 1, MOYENNE: 2, INFO: 3 };
  return recos.sort(
    (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority],
  );
}

// ─────────────────────────────────────────────
// Build Report
// ─────────────────────────────────────────────
const recos = generateRecos();

const recosSection = recos
  .map((r) => {
    const icons: Record<string, string> = {
      CRITIQUE: "🚨",
      HAUTE: "⚠️",
      MOYENNE: "🔵",
      INFO: "ℹ️",
    };
    return `### ${icons[r.priority]} [${r.priority}] ${r.title}\n\n${r.detail}\n`;
  })
  .join("\n");

const fpTable =
  fpCount === 0
    ? "_Aucun faux positif détecté. ✅_"
    : [
        "| Label | Score | Patterns détectés | Note |",
        "|---|---|---|---|",
        ...falsePositives.map(
          (r: any) =>
            `| ${r.label} | ${r.score} | ${(r.patterns || []).join(", ") || "—"} | ${r.note || "—"} |`,
        ),
      ].join("\n");

const fnTable =
  fnCount === 0
    ? "_Aucun faux négatif détecté. ✅_"
    : [
        "| Label | URL | Note |",
        "|---|---|---|",
        ...falseNegatives.map(
          (r: any) =>
            `| ${r.label} | \`${truncate(r.url, 70)}\` | ${r.note || "—"} |`,
        ),
      ].join("\n");

const errTable =
  errors.length === 0
    ? "_Aucune erreur d'exécution._"
    : [
        "| Label | Erreur |",
        "|---|---|",
        ...errors.map((e: any) => `| ${e.label} | ${e.error} |`),
      ].join("\n");

// Toutes les URLs légitimes pour inspection
const legitimateResults = allResults.filter((r: any) => !r.expectedMalicious);
const legitTable = [
  "| Statut | Label | Score | Patterns | Note |",
  "|---|---|---|---|---|",
  ...legitimateResults.map((r: any) => {
    const icon = r.passed ? "✅" : "🟡 FP";
    return `| ${icon} | ${r.label} | ${r.score} | ${(r.patterns || []).join(", ") || "—"} | ${r.note || "—"} |`;
  }),
].join("\n");

// ─────────────────────────────────────────────
// Final Markdown
// ─────────────────────────────────────────────
const scoreEmoji =
  passed / total >= 0.95 ? "🟢" : passed / total >= 0.8 ? "🟡" : "🔴";

const markdown = `# Rapport de Sécurité — StruLink URL Scanner
 
> Généré le **${date}** · ${total} cas testés · Taux de réussite global : **${passRate}%** ${scoreEmoji}
 
---
 
## Vue d'ensemble
 
| Métrique | Valeur |
|---|---|
| Total de tests | **${total}** |
| ✅ Réussis | **${passed}** (${passRate}%) |
| 🟡 Faux Positifs (URL légitimes bloquées) | **${badge(fpCount)} ${fpCount}** |
| 🔴 Faux Négatifs (attaques non détectées) | **${badge(fnCount, 1, 2)} ${fnCount}** |
| 💥 Erreurs d'exécution | **${errors.length}** |
 
> **Faux positifs** = URLs légitimes signalées à tort comme malveillantes → impact sur l'expérience développeur/utilisateur.  
> **Faux négatifs** = attaques réelles non détectées → risque de sécurité.
 
---
 
## Résultats par catégorie
 
${categoryTable()}
 
---
 
## Recommandations
 
${recosSection}
 
---
 
## Détail — Faux Positifs
 
${fpTable}
 
---
 
## Détail — Faux Négatifs
 
${fnTable}
 
---
 
## Inventaire — URLs légitimes testées
 
Ces URLs doivent toutes passer **sans alerte** pour garantir une bonne expérience développeur dans Express.
 
${legitTable}
 
---
 
## Erreurs d'exécution
 
${errTable}
 
---
 
## Analyse des patterns déclencheurs
 
Les patterns ci-dessous ont déclenché le plus de faux positifs ou faux négatifs :
 
${(() => {
  const patternCount: Record<string, number> = {};
  for (const r of allResults) {
    if (r.isFalsePositive || r.isFalseNegative) {
      for (const p of r.patterns || []) {
        patternCount[p] = (patternCount[p] ?? 0) + 1;
      }
    }
  }
  const sorted = Object.entries(patternCount).sort(([, a], [, b]) => b - a);
  if (sorted.length === 0) return "_Aucun pattern problématique identifié._";
  return [
    "| Pattern | Occurrences dans les erreurs |",
    "|---|---|",
    ...sorted.map(([p, n]) => `| \`${p}\` | ${n} |`),
  ].join("\n");
})()}
 
---
 
## Recommandations pour patterns spécifiques
 
### Prévenir les faux positifs sur les sous-chaînes
 
Utiliser des **word boundaries** ou du contexte pour éviter les collisions :
 
\`\`\`ts
// ❌ Trop large — va matcher "transcript", "description"…
/script/i
 
// ✅ Contextualisé — balises HTML uniquement
/(?:<|%3C)\\s*script[\\s>]/i
\`\`\`
 
### Normalisation avant scan
 
\`\`\`ts
function normalizeUrl(url: string): string {
  let decoded = url;
  // Double-decode URL encoding
  for (let i = 0; i < 3; i++) {
    try { decoded = decodeURIComponent(decoded); } catch { break; }
  }
  // HTML entity decode
  decoded = decoded
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&").replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
  // Unicode unescape
  decoded = decoded.replace(/\\\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  return decoded;
}
\`\`\`
 
### Détection IPs internes (SSRF)
 
\`\`\`ts
function isPrivateIP(ip: string): boolean {
  // Decimal IP → convertir en notation classique
  if (/^\\d+$/.test(ip)) {
    const n = parseInt(ip);
    const a = (n >> 24) & 255, b = (n >> 16) & 255;
    ip = \`\${a}.\${b}.\${(n >> 8) & 255}.\${n & 255}\`;
  }
  return /^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.|0\\.0\\.0\\.0)/.test(ip);
}
\`\`\`
 
---
 
_Rapport généré automatiquement par \`report-generator.ts\` · StruLink Security Suite_
`;

await Bun.write("security-report.md", markdown);
console.log(`\n✅ Rapport généré : security-report.md`);
console.log(
  `   ${total} cas · ${passRate}% de réussite · ${fpCount} FP · ${fnCount} FN\n`,
);
