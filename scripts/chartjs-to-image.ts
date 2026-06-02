import ChartJsImage from "chartjs-to-image";
import fs from "fs";

// Charger les résultats du bench
const data = JSON.parse(fs.readFileSync("benchmark-results.json", "utf-8"));
const sample = data.sample;

// Préparer les données pour le graphique
const labels = sample.map((s: any) => {
  const urlObj = new URL(s.url);
  return urlObj.searchParams.get("_b") || "";
});
const times = sample.map((s: any) => s.timeMs);

const chart = new ChartJsImage();
chart.setConfig({
  type: "line",
  data: {
    labels: labels,
    datasets: [
      {
        label: "Temps d'analyse (ms)",
        data: times,
        borderColor: "rgb(75, 192, 192)",
        backgroundColor: "rgba(75, 192, 192, 0.1)",
        fill: true,
        tension: 0.1,
      },
    ],
  },
  options: {
    title: {
      display: true,
      text: "Courbe d'échauffement (Warm-up Curve) - 25 premières requêtes",
    },
    scales: {
      xAxes: [
        { scaleLabel: { display: true, labelString: "Index de la requête" } },
      ],
      yAxes: [
        {
          scaleLabel: { display: true, labelString: "Temps (ms)" },
          ticks: { beginAtZero: true },
        },
      ],
    },
  },
});

async function generate() {
  console.log("Génération du graphique en cours...");
  await chart.toFile("benchmark-chart.png");
  console.log("Graphique sauvegardé sous 'benchmark-chart.png' !");
}

generate();
