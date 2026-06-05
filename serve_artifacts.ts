import path from "node:path";

const args = Bun.argv.slice(2);

function getArg(name: string, fallback: string): string {
  const idx = args.indexOf(name);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : fallback;
}

const port = Number.parseInt(getArg("--port", "3000"), 10);
const rootArg = getArg("--dir", "honeypot/analysis/artifacts");
const rootDir = path.resolve(process.cwd(), rootArg);

const mimeTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

function fileResponse(filePath: string): Response {
  const ext = path.extname(filePath).toLowerCase();
  const type = mimeTypes[ext] ?? "application/octet-stream";
  return new Response(Bun.file(filePath), {
    headers: {
      "content-type": type,
      "cache-control": "no-store",
    },
  });
}

function notFound(): Response {
  return new Response("Not found", { status: 404 });
}

const server = Bun.serve({
  port,
  routes: {
    "/": async () => {
      const filePath = path.join(rootDir, "cowrie_state_machine.html");
      const file = Bun.file(filePath);
      return (await file.exists()) ? fileResponse(filePath) : notFound();
    },
    "/cowrie_state_machine.html": async () => {
      const filePath = path.join(rootDir, "cowrie_state_machine.html");
      const file = Bun.file(filePath);
      return (await file.exists()) ? fileResponse(filePath) : notFound();
    },
    "/cowrie_state_machine.svg": async () => {
      const filePath = path.join(rootDir, "cowrie_state_machine.svg");
      const file = Bun.file(filePath);
      return (await file.exists()) ? fileResponse(filePath) : notFound();
    },
    "/cowrie_state_machine_graph.json": async () => {
      const filePath = path.join(rootDir, "cowrie_state_machine_graph.json");
      const file = Bun.file(filePath);
      return (await file.exists()) ? fileResponse(filePath) : notFound();
    },
    "/cowrie_state_machine.scene.json": async () => {
      const filePath = path.join(rootDir, "cowrie_state_machine.scene.json");
      const file = Bun.file(filePath);
      return (await file.exists()) ? fileResponse(filePath) : notFound();
    },
    "/cowrie_summary.md": async () => {
      const filePath = path.join(rootDir, "cowrie_summary.md");
      const file = Bun.file(filePath);
      return (await file.exists()) ? fileResponse(filePath) : notFound();
    },
    "/favicon.ico": () => new Response(null, { status: 204 }),
  },
});

console.log(`Serving ${rootDir}`);
console.log(`Open http://localhost:${server.port}/`);
