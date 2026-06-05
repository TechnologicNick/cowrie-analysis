import fs from "node:fs/promises";
import path from "node:path";
import ELK from "elkjs/lib/elk.bundled.js";

const NODE_COLORS = {
  root: "#1f4e79",
  event: "#7c8b96",
  "fingerprinting/recon": "#d47f00",
  credential_persistence: "#b33c00",
  download_exec: "#2e8b57",
  proxy_tunnel: "#3f51b5",
  "cleanup/evasion": "#7b1fa2",
  other: "#4b5d67",
  terminal: "#1b1b1b",
};

const EDGE_SENSOR_COLORS = {
  baseline_only: "#1f4e79",
  hostname_only: "#00796b",
  both: "#625971",
};

function escapeXml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function rgba(hex, alpha) {
  const clean = hex.replace("#", "");
  const r = Number.parseInt(clean.slice(0, 2), 16);
  const g = Number.parseInt(clean.slice(2, 4), 16);
  const b = Number.parseInt(clean.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

function nodeVisualSize(node) {
  const baseWidth = 54;
  const textWidth = Math.min(620, node.display_label.length * 7.2);
  const width = Math.max(baseWidth, textWidth + 26);
  const height = node.node_type === "command" ? 34 : 30;
  return { width, height };
}

function edgeStrokeWidth(totalCount) {
  return Math.max(1.2, Math.min(16, 1.2 + Math.log10(Math.max(1, totalCount)) * 3.2));
}

function nodeStrokeWidth(totalCount) {
  return Math.max(0.8, Math.min(2.6, 0.8 + Math.log10(Math.max(1, totalCount))));
}

function buildElkGraph(graphData) {
  const children = [...graphData.nodes]
    .sort((a, b) => (a.step_index - b.step_index) || (a.model_order - b.model_order) || a.label.localeCompare(b.label))
    .map((node) => {
      const { width, height } = nodeVisualSize(node);
      return {
        id: node.node_id,
        width,
        height,
        layoutOptions: {
          "org.eclipse.elk.partitioning.partition": String(node.step_index),
        },
      };
    });

  const edges = graphData.edges.map((edge, index) => ({
    id: `e${index}`,
    sources: [edge.source_id],
    targets: [edge.target_id],
  }));

  return {
    id: "cowrie-state-machine",
    children,
    edges,
    layoutOptions: {
      "org.eclipse.elk.algorithm": "org.eclipse.elk.layered",
      "org.eclipse.elk.direction": "RIGHT",
      "org.eclipse.elk.edgeRouting": "ORTHOGONAL",
      "org.eclipse.elk.partitioning.activate": "true",
      "org.eclipse.elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
      "org.eclipse.elk.layered.crossingMinimization.forceNodeModelOrder": "true",
      "org.eclipse.elk.layered.nodePlacement.favorStraightEdges": "true",
      "org.eclipse.elk.layered.spacing.nodeNodeBetweenLayers": "90",
      "org.eclipse.elk.layered.spacing.edgeNodeBetweenLayers": "48",
      "org.eclipse.elk.spacing.nodeNode": "90",
      "org.eclipse.elk.spacing.edgeNode": "50",
      "org.eclipse.elk.spacing.edgeEdge": "24",
      "org.eclipse.elk.padding": "[top=40,left=40,bottom=40,right=40]",
    },
  };
}

function polylinePath(section) {
  const points = [section.startPoint, ...(section.bendPoints ?? []), section.endPoint];
  const [first, ...rest] = points;
  return `M ${first.x} ${first.y} ` + rest.map((point) => `L ${point.x} ${point.y}`).join(" ");
}

async function main() {
  const [, , inputArg, outputArg] = process.argv;
  if (!inputArg || !outputArg) {
    console.error("Usage: node render_state_machine.mjs <graph.json> <output.svg>");
    process.exit(1);
  }

  const inputPath = path.resolve(inputArg);
  const outputPath = path.resolve(outputArg);
  const htmlOutputPath = outputPath.replace(/\.svg$/i, ".html");
  const raw = await fs.readFile(inputPath, "utf-8");
  const graphData = JSON.parse(raw);

  const nodeMeta = new Map(graphData.nodes.map((node) => [node.node_id, node]));
  const edgeMeta = new Map(
    graphData.edges.map((edge, index) => [`e${index}`, edge]),
  );

  const elk = new ELK();
  const laidOut = await elk.layout(buildElkGraph(graphData));

  const width = Math.ceil((laidOut.width ?? 1000) + 60);
  const height = Math.ceil((laidOut.height ?? 1000) + 60);

  const edgeSvg = [];
  for (const edge of laidOut.edges ?? []) {
    const meta = edgeMeta.get(edge.id);
    if (!meta) continue;
    const color = EDGE_SENSOR_COLORS[meta.sensor_mix] ?? EDGE_SENSOR_COLORS.both;
    const strokeWidth = edgeStrokeWidth(meta.total_count);
    const sections = edge.sections ?? [];
    for (const section of sections) {
      edgeSvg.push(
        `<path d="${polylinePath(section)}" fill="none" stroke="${rgba(color, 0.42)}" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round">` +
          `<title>${escapeXml(`${meta.source_label} -> ${meta.target_label}\nbaseline=${meta.baseline_count}\nhostname=${meta.hostname_count}\ntotal=${meta.total_count}`)}</title>` +
        `</path>`
      );
    }
  }

  const nodeSvg = [];
  for (const node of laidOut.children ?? []) {
    const meta = nodeMeta.get(node.id);
    if (!meta) continue;
    const colorKey = meta.color_key;
    const fill = NODE_COLORS[colorKey] ?? NODE_COLORS.other;
    const stroke = rgba(fill, 0.95);
    const textColor = meta.node_type === "terminal" || colorKey === "root" ? "#f8f6f1" : "#111111";
    const radius = meta.node_type === "command" ? 8 : 6;
    const x = node.x ?? 0;
    const y = node.y ?? 0;
    const widthNode = node.width ?? 100;
    const heightNode = node.height ?? 30;

    nodeSvg.push(
      `<g class="node node-${escapeXml(meta.node_type)}" transform="translate(${x},${y})">` +
        `<title>${escapeXml(`${meta.full_display_label}\nbaseline=${meta.baseline_count}\nhostname=${meta.hostname_count}\ntotal=${meta.total_count}\nstep=${meta.step_index}`)}</title>` +
        `<rect x="0" y="0" width="${widthNode}" height="${heightNode}" rx="${radius}" ry="${radius}" fill="${fill}" fill-opacity="0.92" stroke="${stroke}" stroke-width="${nodeStrokeWidth(meta.total_count)}" />` +
        `<text x="12" y="${Math.round(heightNode / 2) + 4}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="${textColor}">${escapeXml(meta.display_label)}</text>` +
      `</g>`
    );
  }

  const stepLabels = [];
  const maxStep = graphData.meta.max_step_index ?? 0;
  const seenSteps = new Set();
  for (const node of laidOut.children ?? []) {
    const meta = nodeMeta.get(node.id);
    if (!meta || seenSteps.has(meta.step_index)) continue;
    seenSteps.add(meta.step_index);
    stepLabels.push(
      `<text x="${(node.x ?? 0) + 4}" y="20" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#444">step ${meta.step_index}</text>`
    );
  }
  if (!seenSteps.has(0)) {
    stepLabels.push(`<text x="4" y="20" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#444">step 0</text>`);
  }

  const legendEntries = [
    ["root", "root"],
    ["event", "event"],
    ["terminal", "end"],
    ["fingerprinting/recon", "cmd recon"],
    ["credential_persistence", "cmd creds"],
    ["download_exec", "cmd download"],
    ["proxy_tunnel", "cmd tunnel"],
    ["cleanup/evasion", "cmd cleanup"],
    ["other", "cmd other"],
  ];
  const legendSvg = legendEntries.map(([key, label], idx) => {
    const x = 40 + (idx % 3) * 200;
    const y = height - 110 + Math.floor(idx / 3) * 26;
    const fill = NODE_COLORS[key];
    return (
      `<rect x="${x}" y="${y - 12}" width="18" height="18" rx="4" ry="4" fill="${fill}" />` +
      `<text x="${x + 26}" y="${y + 2}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#222">${escapeXml(label)}</text>`
    );
  }).join("");

  const title = `Cowrie Session State Machine (${graphData.meta.session_count} sessions)`;
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <rect x="0" y="0" width="${width}" height="${height}" fill="#f7f3ea" />
  <text x="40" y="28" font-family="Segoe UI, Arial, sans-serif" font-size="20" font-weight="600" fill="#1b1b1b">${escapeXml(title)}</text>
  <text x="40" y="48" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#555">${escapeXml(`sensors=${graphData.meta.sensors.join(", ")}  range=${graphData.meta.from_date ?? "start"}..${graphData.meta.to_date ?? "end"}  nodes=${graphData.meta.node_count}  edges=${graphData.meta.edge_count}  maxStep=${maxStep}`)}</text>
  ${stepLabels.join("\n  ")}
  <g class="edges">
    ${edgeSvg.join("\n    ")}
  </g>
  <g class="nodes">
    ${nodeSvg.join("\n    ")}
  </g>
  <g class="legend">
    ${legendSvg}
  </g>
</svg>`;

  await fs.writeFile(outputPath, svg, "utf-8");

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeXml(title)}</title>
  <style>
    :root {
      --bg: #f7f3ea;
      --panel: #fffaf0;
      --text: #1b1b1b;
      --muted: #5b5b5b;
      --border: #d6cfbe;
      --accent: #1f4e79;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
    }
    .toolbar {
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      gap: 12px;
      align-items: center;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      background: rgba(255, 250, 240, 0.96);
      backdrop-filter: blur(6px);
    }
    .toolbar h1 {
      margin: 0 16px 0 0;
      font-size: 18px;
      font-weight: 600;
    }
    .toolbar button {
      border: 1px solid var(--border);
      background: white;
      color: var(--text);
      border-radius: 8px;
      padding: 8px 12px;
      cursor: pointer;
      font: inherit;
    }
    .toolbar button:hover { border-color: var(--accent); }
    .toolbar .meta {
      margin-left: auto;
      color: var(--muted);
      font-size: 13px;
    }
    .viewport {
      width: 100vw;
      height: calc(100vh - 58px);
      overflow: hidden;
      cursor: grab;
      background:
        radial-gradient(circle at top left, rgba(31,78,121,0.08), transparent 26%),
        linear-gradient(180deg, #fbf8f0 0%, #f3ecdf 100%);
    }
    .viewport.dragging { cursor: grabbing; }
    .canvas {
      transform-origin: 0 0;
      will-change: transform;
      display: inline-block;
      padding: 20px;
    }
    .canvas svg {
      display: block;
      box-shadow: 0 24px 60px rgba(0,0,0,0.10);
      border-radius: 12px;
      background: var(--bg);
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <h1>${escapeXml(title)}</h1>
    <button type="button" id="zoomIn">Zoom In</button>
    <button type="button" id="zoomOut">Zoom Out</button>
    <button type="button" id="resetView">Reset</button>
    <div class="meta">wheel: zoom, drag: pan, range: ${escapeXml((graphData.meta.from_date ?? "start") + ".." + (graphData.meta.to_date ?? "end"))}</div>
  </div>
  <div class="viewport" id="viewport">
    <div class="canvas" id="canvas">
${svg}
    </div>
  </div>
  <script>
    const viewport = document.getElementById('viewport');
    const canvas = document.getElementById('canvas');
    const zoomIn = document.getElementById('zoomIn');
    const zoomOut = document.getElementById('zoomOut');
    const resetView = document.getElementById('resetView');
    let scale = 1;
    let panX = 0;
    let panY = 0;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;

    function applyTransform() {
      canvas.style.transform = 'translate(' + panX + 'px, ' + panY + 'px) scale(' + scale + ')';
    }

    function zoomAt(factor, clientX, clientY) {
      const rect = viewport.getBoundingClientRect();
      const px = clientX - rect.left;
      const py = clientY - rect.top;
      const nextScale = Math.min(8, Math.max(0.15, scale * factor));
      const worldX = (px - panX) / scale;
      const worldY = (py - panY) / scale;
      panX = px - worldX * nextScale;
      panY = py - worldY * nextScale;
      scale = nextScale;
      applyTransform();
    }

    viewport.addEventListener('wheel', (event) => {
      event.preventDefault();
      zoomAt(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.clientX, event.clientY);
    }, { passive: false });

    viewport.addEventListener('mousedown', (event) => {
      dragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
      viewport.classList.add('dragging');
    });

    window.addEventListener('mousemove', (event) => {
      if (!dragging) return;
      panX += event.clientX - lastX;
      panY += event.clientY - lastY;
      lastX = event.clientX;
      lastY = event.clientY;
      applyTransform();
    });

    window.addEventListener('mouseup', () => {
      dragging = false;
      viewport.classList.remove('dragging');
    });

    zoomIn.addEventListener('click', () => zoomAt(1.2, viewport.clientWidth / 2, viewport.clientHeight / 2));
    zoomOut.addEventListener('click', () => zoomAt(1 / 1.2, viewport.clientWidth / 2, viewport.clientHeight / 2));
    resetView.addEventListener('click', () => {
      scale = 1;
      panX = 0;
      panY = 0;
      applyTransform();
    });

    applyTransform();
  </script>
</body>
</html>`;

  await fs.writeFile(htmlOutputPath, html, "utf-8");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
