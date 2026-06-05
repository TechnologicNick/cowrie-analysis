import fs from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import ELK from "elkjs/lib/elk.bundled.js";

const require = createRequire(import.meta.url);
const elkWorkerModule = require("elkjs/lib/elk-worker.min.js");
const ElkWorker = elkWorkerModule.Worker ?? elkWorkerModule.default ?? elkWorkerModule;

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
  const cleaned = String(text).replaceAll(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return cleaned
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

function computeBounds(points) {
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  for (const point of points) {
    minX = Math.min(minX, point.x);
    minY = Math.min(minY, point.y);
    maxX = Math.max(maxX, point.x);
    maxY = Math.max(maxY, point.y);
  }
  return { minX, minY, maxX, maxY };
}

function computeSegmentBounds(startPoint, endPoint) {
  return {
    minX: Math.min(startPoint.x, endPoint.x),
    minY: Math.min(startPoint.y, endPoint.y),
    maxX: Math.max(startPoint.x, endPoint.x),
    maxY: Math.max(startPoint.y, endPoint.y),
  };
}

function buildSceneData(graphData, laidOut, nodeMeta, edgeMeta, width, height, title) {
  const sceneNodes = [];
  for (const node of laidOut.children ?? []) {
    const meta = nodeMeta.get(node.id);
    if (!meta) continue;
    const colorKey = meta.color_key;
    const fill = NODE_COLORS[colorKey] ?? NODE_COLORS.other;
    const stroke = rgba(fill, 0.95);
    const textColor = meta.node_type === "terminal" || colorKey === "root" ? "#f8f6f1" : "#111111";
    const widthNode = node.width ?? 100;
    const heightNode = node.height ?? 30;
    sceneNodes.push({
      id: node.id,
      x: node.x ?? 0,
      y: node.y ?? 0,
      width: widthNode,
      height: heightNode,
      radius: meta.node_type === "command" ? 8 : 6,
      fill,
      stroke,
      strokeWidth: nodeStrokeWidth(meta.total_count),
      text: meta.display_label,
      fullLabel: meta.full_display_label,
      rawLabel: meta.label,
      nodeType: meta.node_type,
      stepIndex: meta.step_index,
      commandFamily: meta.command_family,
      colorKey: meta.color_key,
      sourceEventId: meta.source_eventid ?? "",
      textColor,
      fontSize: 12,
      baselineCount: meta.baseline_count,
      hostnameCount: meta.hostname_count,
      totalCount: meta.total_count,
      topFlows: meta.top_flows ?? [],
      bounds: {
        minX: node.x ?? 0,
        minY: node.y ?? 0,
        maxX: (node.x ?? 0) + widthNode,
        maxY: (node.y ?? 0) + heightNode,
      },
    });
  }

  const sceneEdges = [];
  for (const edge of laidOut.edges ?? []) {
    const meta = edgeMeta.get(edge.id);
    if (!meta) continue;
    const color = EDGE_SENSOR_COLORS[meta.sensor_mix] ?? EDGE_SENSOR_COLORS.both;
    for (const section of edge.sections ?? []) {
      const points = [section.startPoint, ...(section.bendPoints ?? []), section.endPoint];
      for (let index = 0; index < points.length - 1; index += 1) {
        const startPoint = points[index];
        const endPoint = points[index + 1];
        sceneEdges.push({
          id: `${edge.id}:${index}`,
          x1: startPoint.x,
          y1: startPoint.y,
          x2: endPoint.x,
          y2: endPoint.y,
          stroke: rgba(color, 0.42),
          strokeWidth: edgeStrokeWidth(meta.total_count),
          bounds: computeSegmentBounds(startPoint, endPoint),
        });
      }
    }
  }

  const stepLabels = [];
  const seenSteps = new Set();
  for (const node of laidOut.children ?? []) {
    const meta = nodeMeta.get(node.id);
    if (!meta || seenSteps.has(meta.step_index)) continue;
    seenSteps.add(meta.step_index);
    stepLabels.push({
      stepIndex: meta.step_index,
      x: (node.x ?? 0) + 4,
      y: 20,
      text: `step ${meta.step_index}`,
    });
  }
  if (!seenSteps.has(0)) {
    stepLabels.push({ stepIndex: 0, x: 4, y: 20, text: "step 0" });
  }

  const legend = [
    ["root", "root"],
    ["event", "event"],
    ["terminal", "end"],
    ["fingerprinting/recon", "cmd recon"],
    ["credential_persistence", "cmd creds"],
    ["download_exec", "cmd download"],
    ["proxy_tunnel", "cmd tunnel"],
    ["cleanup/evasion", "cmd cleanup"],
    ["other", "cmd other"],
  ].map(([key, label], idx) => ({
    key,
    label,
    fill: NODE_COLORS[key],
    x: 40 + (idx % 3) * 200,
    y: height - 110 + Math.floor(idx / 3) * 26,
  }));

  return {
    meta: graphData.meta,
    title,
    width,
    height,
    nodes: sceneNodes,
    edges: sceneEdges,
    stepLabels,
    legend,
  };
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
  const sceneOutputPath = outputPath.replace(/\.svg$/i, ".scene.json");
  const raw = await fs.readFile(inputPath, "utf-8");
  const graphData = JSON.parse(raw);

  const nodeMeta = new Map(graphData.nodes.map((node) => [node.node_id, node]));
  const edgeMeta = new Map(
    graphData.edges.map((edge, index) => [`e${index}`, edge]),
  );

  const elk = new ELK({
    workerFactory: (url) => new ElkWorker(url),
  });
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
      const points = [section.startPoint, ...(section.bendPoints ?? []), section.endPoint];
      for (let index = 0; index < points.length - 1; index += 1) {
        const startPoint = points[index];
        const endPoint = points[index + 1];
        edgeSvg.push(
          `<line x1="${startPoint.x}" y1="${startPoint.y}" x2="${endPoint.x}" y2="${endPoint.y}" stroke="${rgba(color, 0.42)}" stroke-width="${strokeWidth}" stroke-linecap="round">` +
            `<title>${escapeXml(`${meta.source_label} -> ${meta.target_label}\nbaseline=${meta.baseline_count}\nhostname=${meta.hostname_count}\ntotal=${meta.total_count}`)}</title>` +
          `</line>`
        );
      }
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
  const sceneData = buildSceneData(graphData, laidOut, nodeMeta, edgeMeta, width, height, title);
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
  await fs.writeFile(sceneOutputPath, JSON.stringify(sceneData), "utf-8");

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
      --sidebar-width: 380px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      min-height: 100vh;
    }
    .app {
      display: flex;
      min-height: 100vh;
    }
    .main {
      flex: 1 1 auto;
      min-width: 0;
      display: flex;
      flex-direction: column;
    }
    .toolbar {
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
      position: relative;
      flex: 1 1 auto;
      min-height: 0;
      cursor: grab;
      overflow: hidden;
      background:
        radial-gradient(circle at top left, rgba(31,78,121,0.08), transparent 26%),
        linear-gradient(180deg, #fbf8f0 0%, #f3ecdf 100%);
    }
    .viewport.dragging { cursor: grabbing; }
    .stage {
      width: 100%;
      height: 100%;
      display: block;
    }
    .status {
      position: absolute;
      left: 16px;
      bottom: 16px;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: rgba(255, 250, 240, 0.92);
      color: var(--muted);
      font-size: 12px;
    }
    .tooltip {
      position: absolute;
      z-index: 12;
      min-width: 220px;
      max-width: 320px;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: rgba(255, 250, 240, 0.97);
      box-shadow: 0 10px 24px rgba(0, 0, 0, 0.12);
      pointer-events: none;
      opacity: 0;
      transform: translateY(4px);
      transition: opacity 100ms ease, transform 100ms ease;
    }
    .tooltip.visible {
      opacity: 1;
      transform: translateY(0);
    }
    .tooltip .title {
      margin: 0 0 6px 0;
      font-size: 13px;
      font-weight: 600;
      word-break: break-word;
    }
    .tooltip .meta-line {
      font-size: 12px;
      color: var(--muted);
      margin: 2px 0;
    }
    .sidebar {
      width: var(--sidebar-width);
      flex: 0 0 var(--sidebar-width);
      border-left: 1px solid var(--border);
      background: linear-gradient(180deg, #fffaf0 0%, #f6efdf 100%);
      display: flex;
      flex-direction: column;
      min-height: 100vh;
    }
    .sidebar-header {
      padding: 16px 18px 12px 18px;
      border-bottom: 1px solid var(--border);
    }
    .sidebar-header h2 {
      margin: 0 0 6px 0;
      font-size: 16px;
    }
    .sidebar-header p {
      margin: 0;
      font-size: 13px;
      color: var(--muted);
      line-height: 1.45;
    }
    .sidebar-body {
      padding: 16px 18px 24px 18px;
      overflow: auto;
      flex: 1 1 auto;
    }
    .selection-card {
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.7);
      padding: 14px;
      margin-bottom: 16px;
    }
    .selection-card h3 {
      margin: 0 0 8px 0;
      font-size: 14px;
      line-height: 1.35;
      word-break: break-word;
    }
    .selection-card .meta-line {
      margin: 4px 0;
      font-size: 13px;
      color: var(--muted);
    }
    .selection-actions,
    .flow-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }
    .action-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 9px;
      background: #ffffff;
      color: var(--accent);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
    }
    .action-link:hover {
      border-color: var(--accent);
    }
    .flow-list {
      display: grid;
      gap: 12px;
    }
    .flow-item {
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.7);
      padding: 12px 13px;
    }
    .flow-item .counts {
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .flow-steps {
      display: grid;
      gap: 6px;
    }
    .flow-step {
      border-radius: 9px;
      padding: 8px 10px;
      font-size: 12px;
      line-height: 1.35;
      word-break: break-word;
    }
    .empty-state {
      border: 1px dashed var(--border);
      border-radius: 12px;
      padding: 16px;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.4);
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <div class="app">
    <main class="main">
      <div class="toolbar">
        <h1>${escapeXml(title)}</h1>
        <button type="button" id="zoomIn">Zoom In</button>
        <button type="button" id="zoomOut">Zoom Out</button>
        <button type="button" id="resetView">Reset</button>
        <div class="meta">wheel: zoom, drag: pan, click node: inspect flows, range: ${escapeXml((graphData.meta.from_date ?? "start") + ".." + (graphData.meta.to_date ?? "end"))}</div>
      </div>
      <div class="viewport" id="viewport">
        <canvas class="stage" id="stage"></canvas>
        <div class="tooltip" id="tooltip"></div>
        <div class="status" id="status">loading scene...</div>
      </div>
    </main>
    <aside class="sidebar">
      <div class="sidebar-header">
        <h2>Node Flows</h2>
        <p>Hover a node for per-sensor session counts. Click a node to inspect the dominant full start-to-end flows that pass through it.</p>
      </div>
      <div class="sidebar-body" id="sidebarBody">
        <div class="empty-state">No node selected.</div>
      </div>
    </aside>
  </div>
  <script>
    const viewport = document.getElementById('viewport');
    const stage = document.getElementById('stage');
    const ctx = stage.getContext('2d');
    const status = document.getElementById('status');
    const tooltip = document.getElementById('tooltip');
    const sidebarBody = document.getElementById('sidebarBody');
    const zoomIn = document.getElementById('zoomIn');
    const zoomOut = document.getElementById('zoomOut');
    const resetView = document.getElementById('resetView');
    const sceneUrl = '/cowrie_state_machine.scene.json';
    const splunkBaseUrl = 'http://10.20.0.36:8000/en-US/app/search/search?q=';
    const splunkTimeSuffix = '&earliest=0&latest=';
    const nodeColors = ${JSON.stringify(NODE_COLORS)};
    let scene = null;
    let scale = 1;
    let panX = 20;
    let panY = 20;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    let deviceScale = Math.max(1, window.devicePixelRatio || 1);
    let drawQueued = false;
    let movedDuringDrag = false;
    let hoveredNodeId = null;
    let selectedNodeId = null;
    let velocityX = 0;
    let velocityY = 0;
    let inertiaFrame = 0;
    let lastDragAt = 0;

    function escapeHtml(text) {
      return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function intersects(a, b) {
      return !(a.maxX < b.minX || a.minX > b.maxX || a.maxY < b.minY || a.minY > b.maxY);
    }

    function resizeCanvas() {
      deviceScale = Math.max(1, window.devicePixelRatio || 1);
      const widthCss = viewport.clientWidth;
      const heightCss = viewport.clientHeight;
      stage.width = Math.floor(widthCss * deviceScale);
      stage.height = Math.floor(heightCss * deviceScale);
      stage.style.width = widthCss + 'px';
      stage.style.height = heightCss + 'px';
      queueDraw();
    }

    function updateStatus() {
      const nodeCount = scene ? scene.nodes.length : 0;
      const edgeCount = scene ? scene.edges.length : 0;
      const selectedNode = getSelectedNode();
      const selectedText = selectedNode ? ' | selected ' + selectedNode.fullLabel : '';
      status.textContent = 'zoom ' + scale.toFixed(2) + 'x | pan ' + Math.round(panX) + ', ' + Math.round(panY) + ' | nodes ' + nodeCount + ' | edges ' + edgeCount + selectedText;
    }

    function stopInertia() {
      if (inertiaFrame) {
        window.cancelAnimationFrame(inertiaFrame);
        inertiaFrame = 0;
      }
    }

    function getSelectedNode() {
      if (!scene || !selectedNodeId) return null;
      return scene.nodes.find((node) => node.id === selectedNodeId) || null;
    }

    function getHoveredNode() {
      if (!scene || !hoveredNodeId) return null;
      return scene.nodes.find((node) => node.id === hoveredNodeId) || null;
    }

    function worldFromClient(clientX, clientY) {
      const rect = viewport.getBoundingClientRect();
      const px = clientX - rect.left;
      const py = clientY - rect.top;
      return {
        x: (px - panX) / scale,
        y: (py - panY) / scale,
        px,
        py,
      };
    }

    function pickNode(clientX, clientY) {
      if (!scene) return null;
      const point = worldFromClient(clientX, clientY);
      for (let index = scene.nodes.length - 1; index >= 0; index -= 1) {
        const node = scene.nodes[index];
        if (point.x >= node.bounds.minX && point.x <= node.bounds.maxX && point.y >= node.bounds.minY && point.y <= node.bounds.maxY) {
          return node;
        }
      }
      return null;
    }

    function updateTooltip(node, clientX, clientY) {
      if (!node) {
        tooltip.classList.remove('visible');
        tooltip.innerHTML = '';
        return;
      }
      const extra = node.commandFamily ? '<div class="meta-line">family: ' + escapeHtml(node.commandFamily) + '</div>' : '';
      tooltip.innerHTML =
        '<div class="title">' + escapeHtml(node.fullLabel) + '</div>' +
        '<div class="meta-line">step: ' + node.stepIndex + '</div>' +
        '<div class="meta-line">baseline sessions: ' + node.baselineCount + '</div>' +
        '<div class="meta-line">hostname sessions: ' + node.hostnameCount + '</div>' +
        '<div class="meta-line">total sessions: ' + node.totalCount + '</div>' +
        extra;
      const rect = viewport.getBoundingClientRect();
      const offsetX = 18;
      const offsetY = 18;
      const maxLeft = Math.max(8, rect.width - 340);
      const maxTop = Math.max(8, rect.height - 170);
      const left = Math.min(maxLeft, Math.max(8, clientX - rect.left + offsetX));
      const top = Math.min(maxTop, Math.max(8, clientY - rect.top + offsetY));
      tooltip.style.left = left + 'px';
      tooltip.style.top = top + 'px';
      tooltip.classList.add('visible');
    }

    function renderSidebar(node) {
      if (!node) {
        sidebarBody.innerHTML = '<div class="empty-state">No node selected.</div>';
        return;
      }
      const flowItems = (node.topFlows || []).map((flow, index) => {
        const stepsHtml = (flow.steps || []).map((step) => {
          const fill = nodeColors[step.color_key] || nodeColors.other;
          const textColor = (step.color_key === 'root' || step.color_key === 'terminal') ? '#f8f6f1' : '#111111';
          return '<div class="flow-step" style="background:' + escapeHtml(fill) + '; color:' + escapeHtml(textColor) + ';">' + escapeHtml(step.display_label) + '</div>';
        }).join('');
        const sessionLinks = (flow.sample_sessions || []).map((sample) =>
          '<a class="action-link" target="_blank" rel="noreferrer" href="' + escapeHtml(buildSplunkUrlForSession(sample)) + '">' +
            'Open ' + escapeHtml(sample.sensor) + ' ' + escapeHtml(sample.session) +
          '</a>'
        ).join('');
        return (
        '<article class="flow-item">' +
          '<div class="counts">#' + (index + 1) + ' | total ' + flow.total_count + ' | baseline ' + flow.baseline_count + ' | hostname ' + flow.hostname_count + '</div>' +
          '<div class="flow-steps">' + stepsHtml + '</div>' +
          (sessionLinks ? '<div class="flow-actions">' + sessionLinks + '</div>' : '') +
        '</article>'
        );
      }).join('');
      const familyLine = node.commandFamily ? '<div class="meta-line">family: ' + escapeHtml(node.commandFamily) + '</div>' : '';
      const nodeLink = buildSplunkUrlForNode(node);
      const nodeActions = nodeLink
        ? '<div class="selection-actions"><a class="action-link" target="_blank" rel="noreferrer" href="' + escapeHtml(nodeLink) + '">Open Node In Splunk</a></div>'
        : '';
      sidebarBody.innerHTML =
        '<section class="selection-card">' +
          '<h3>' + escapeHtml(node.fullLabel) + '</h3>' +
          '<div class="meta-line">step ' + node.stepIndex + '</div>' +
          '<div class="meta-line">baseline sessions: ' + node.baselineCount + '</div>' +
          '<div class="meta-line">hostname sessions: ' + node.hostnameCount + '</div>' +
          '<div class="meta-line">total sessions: ' + node.totalCount + '</div>' +
          familyLine +
          nodeActions +
        '</section>' +
        ((node.topFlows && node.topFlows.length > 0)
          ? '<div class="flow-list">' + flowItems + '</div>'
          : '<div class="empty-state">No full-path summaries were recorded for this node.</div>');
    }

    function buildSplunkUrl(query) {
      return splunkBaseUrl + encodeURIComponent(query) + splunkTimeSuffix;
    }

    function escapeSplunkValue(value) {
      return JSON.stringify(String(value)).slice(1, -1);
    }

    function escapeRegex(value) {
      return String(value).replace(/[|\\\\{}()\\[\\]^$+*?.]/g, '\\\\$&');
    }

    function buildCommandPrefilter(command) {
      const candidates = String(command)
        .split(/\\s+/)
        .map((token) => token.replace(/^["'()\\[\\]{};,:]+|["'()\\[\\]{};,:]+$/g, '').replaceAll('*', ''))
        .filter((token) => token.length >= 4 && /[A-Za-z0-9]/.test(token));
      if (candidates.length === 0) {
        return '';
      }
      candidates.sort((left, right) => right.length - left.length || left.localeCompare(right));
      return candidates[0];
    }

    function buildSplunkUrlForNode(node) {
      let query = 'search index="cowrie"';
      if (node.nodeType === 'command') {
        const prefilter = buildCommandPrefilter(node.rawLabel);
        query += ' eventid="cowrie.command.input"';
        if (prefilter) {
          query += ' "' + escapeSplunkValue(prefilter) + '"';
        }
        query += ' | regex input="^' + escapeSplunkValue(escapeRegex(node.rawLabel)) + '$"';
      } else if (node.sourceEventId) {
        query += ' eventid="' + escapeSplunkValue(node.sourceEventId) + '"';
      } else if (node.nodeType === 'root') {
        return buildSplunkUrl(query);
      } else {
        return '';
      }
      return buildSplunkUrl(query);
    }

    function buildSplunkUrlForSession(sample) {
      const sessionValue = escapeSplunkValue(sample.session);
      return buildSplunkUrl('search index="cowrie" session="' + sessionValue + '"');
    }

    function drawBackground(widthCss, heightCss) {
      ctx.fillStyle = '#f3ecdf';
      ctx.fillRect(0, 0, widthCss, heightCss);
      const gradient = ctx.createRadialGradient(0, 0, 0, 0, 0, Math.max(widthCss, heightCss) * 0.35);
      gradient.addColorStop(0, 'rgba(31,78,121,0.10)');
      gradient.addColorStop(1, 'rgba(31,78,121,0)');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, widthCss, heightCss);
    }

    function draw() {
      drawQueued = false;
      const widthCss = stage.width / deviceScale;
      const heightCss = stage.height / deviceScale;
      ctx.setTransform(deviceScale, 0, 0, deviceScale, 0, 0);
      drawBackground(widthCss, heightCss);
      if (!scene) {
        updateStatus();
        return;
      }
      const viewMinX = (-panX) / scale;
      const viewMinY = (-panY) / scale;
      const viewMaxX = (widthCss - panX) / scale;
      const viewMaxY = (heightCss - panY) / scale;
      const viewBounds = {
        minX: Math.max(0, viewMinX),
        minY: Math.max(0, viewMinY),
        maxX: Math.min(scene.width, viewMaxX),
        maxY: Math.min(scene.height, viewMaxY),
      };

      if (viewBounds.minX < viewBounds.maxX && viewBounds.minY < viewBounds.maxY) {
        ctx.save();
        ctx.translate(panX, panY);
        ctx.scale(scale, scale);

        ctx.shadowColor = 'rgba(0,0,0,0.12)';
        ctx.shadowBlur = 22;
        ctx.shadowOffsetY = 10;
        ctx.fillStyle = '#f7f3ea';
        ctx.fillRect(viewBounds.minX, viewBounds.minY, viewBounds.maxX - viewBounds.minX, viewBounds.maxY - viewBounds.minY);
        ctx.shadowColor = 'transparent';

        for (const edge of scene.edges) {
          if (!intersects(edge.bounds, viewBounds)) continue;
          ctx.beginPath();
          ctx.moveTo(edge.x1, edge.y1);
          ctx.lineTo(edge.x2, edge.y2);
          ctx.strokeStyle = edge.stroke;
          ctx.lineWidth = edge.strokeWidth;
          ctx.lineCap = 'round';
          ctx.lineJoin = 'round';
          ctx.stroke();
        }

        for (const node of scene.nodes) {
          if (!intersects(node.bounds, viewBounds)) continue;
          const x = node.x;
          const y = node.y;
          const w = node.width;
          const h = node.height;
          const r = node.radius;
          ctx.beginPath();
          ctx.moveTo(x + r, y);
          ctx.lineTo(x + w - r, y);
          ctx.quadraticCurveTo(x + w, y, x + w, y + r);
          ctx.lineTo(x + w, y + h - r);
          ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
          ctx.lineTo(x + r, y + h);
          ctx.quadraticCurveTo(x, y + h, x, y + h - r);
          ctx.lineTo(x, y + r);
          ctx.quadraticCurveTo(x, y, x + r, y);
          ctx.closePath();
          ctx.fillStyle = node.fill;
          ctx.globalAlpha = 0.92;
          ctx.fill();
          ctx.globalAlpha = 1;
          ctx.strokeStyle = node.stroke;
          ctx.lineWidth = node.strokeWidth;
          ctx.stroke();
          if (node.id === selectedNodeId) {
            ctx.strokeStyle = '#0f3558';
            ctx.lineWidth = Math.max(2.4, node.strokeWidth + 1.4);
            ctx.stroke();
          } else if (node.id === hoveredNodeId) {
            ctx.strokeStyle = '#111111';
            ctx.lineWidth = Math.max(1.8, node.strokeWidth + 0.8);
            ctx.stroke();
          }
          ctx.fillStyle = node.textColor;
          ctx.font = node.fontSize + 'px Segoe UI, Arial, sans-serif';
          ctx.fillText(node.text, x + 12, y + Math.round(h / 2) + 4);
        }

        ctx.fillStyle = '#444';
        ctx.font = '12px Segoe UI, Arial, sans-serif';
        for (const label of scene.stepLabels) {
          if (label.x < viewBounds.minX - 100 || label.x > viewBounds.maxX + 100) continue;
          ctx.fillText(label.text, label.x, label.y);
        }

        ctx.fillStyle = '#222';
        ctx.font = '12px Segoe UI, Arial, sans-serif';
        for (const item of scene.legend) {
          const legendBounds = { minX: item.x, minY: item.y - 12, maxX: item.x + 160, maxY: item.y + 8 };
          if (!intersects(legendBounds, viewBounds)) continue;
          ctx.fillStyle = item.fill;
          ctx.fillRect(item.x, item.y - 12, 18, 18);
          ctx.fillStyle = '#222';
          ctx.fillText(item.label, item.x + 26, item.y + 2);
        }

        ctx.restore();
      }
      updateStatus();
    }

    function queueDraw() {
      if (drawQueued) return;
      drawQueued = true;
      window.requestAnimationFrame(draw);
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
      queueDraw();
    }

    viewport.addEventListener('wheel', (event) => {
      event.preventDefault();
      zoomAt(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.clientX, event.clientY);
    }, { passive: false });

    viewport.addEventListener('mousedown', (event) => {
      stopInertia();
      dragging = true;
      movedDuringDrag = false;
      velocityX = 0;
      velocityY = 0;
      lastX = event.clientX;
      lastY = event.clientY;
      lastDragAt = performance.now();
      viewport.classList.add('dragging');
    });

    window.addEventListener('mousemove', (event) => {
      if (dragging) {
        const dx = event.clientX - lastX;
        const dy = event.clientY - lastY;
        const now = performance.now();
        const dt = Math.max(8, now - lastDragAt);
        if (Math.abs(dx) > 0 || Math.abs(dy) > 0) {
          movedDuringDrag = true;
        }
        panX += dx;
        panY += dy;
        velocityX = dx / dt * 16.6667;
        velocityY = dy / dt * 16.6667;
        lastX = event.clientX;
        lastY = event.clientY;
        lastDragAt = now;
        tooltip.classList.remove('visible');
        queueDraw();
        return;
      }
      const nextNode = pickNode(event.clientX, event.clientY);
      const nextId = nextNode ? nextNode.id : null;
      if (nextId !== hoveredNodeId) {
        hoveredNodeId = nextId;
        viewport.style.cursor = nextNode ? 'pointer' : 'grab';
        queueDraw();
      }
      updateTooltip(nextNode, event.clientX, event.clientY);
    });

    window.addEventListener('mouseup', () => {
      const shouldStartInertia = dragging && (Math.abs(velocityX) > 0.4 || Math.abs(velocityY) > 0.4);
      dragging = false;
      viewport.classList.remove('dragging');
      if (shouldStartInertia) {
        startInertia();
      }
    });

    viewport.addEventListener('mouseleave', () => {
      if (hoveredNodeId !== null) {
        hoveredNodeId = null;
        viewport.style.cursor = 'grab';
        queueDraw();
      }
      tooltip.classList.remove('visible');
    });

    viewport.addEventListener('click', (event) => {
      if (movedDuringDrag) {
        movedDuringDrag = false;
        return;
      }
      const node = pickNode(event.clientX, event.clientY);
      selectedNodeId = node ? node.id : null;
      renderSidebar(node);
      queueDraw();
    });

    zoomIn.addEventListener('click', () => zoomAt(1.2, viewport.clientWidth / 2, viewport.clientHeight / 2));
    zoomOut.addEventListener('click', () => zoomAt(1 / 1.2, viewport.clientWidth / 2, viewport.clientHeight / 2));
    resetView.addEventListener('click', () => {
      stopInertia();
      scale = 1;
      panX = 20;
      panY = 20;
      velocityX = 0;
      velocityY = 0;
      queueDraw();
    });

    window.addEventListener('resize', resizeCanvas);

    async function loadScene() {
      try {
        const response = await fetch(sceneUrl, { cache: 'no-store' });
        if (!response.ok) {
          status.textContent = 'failed to fetch scene: ' + response.status;
          return;
        }
        scene = await response.json();
        renderSidebar(null);
        resizeCanvas();
      } catch (error) {
        status.textContent = 'failed to fetch scene over HTTP';
      }
    }

    function startInertia() {
      stopInertia();
      const friction = 0.92;
      const minVelocity = 0.08;
      const tick = () => {
        panX += velocityX;
        panY += velocityY;
        velocityX *= friction;
        velocityY *= friction;
        queueDraw();
        if (Math.abs(velocityX) < minVelocity && Math.abs(velocityY) < minVelocity) {
          velocityX = 0;
          velocityY = 0;
          inertiaFrame = 0;
          return;
        }
        inertiaFrame = window.requestAnimationFrame(tick);
      };
      inertiaFrame = window.requestAnimationFrame(tick);
    }

    resizeCanvas();
    loadScene();
  </script>
</body>
</html>`;

  await fs.writeFile(htmlOutputPath, html, "utf-8");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
