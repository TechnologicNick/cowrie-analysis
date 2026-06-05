# Cowrie analysis

## Local workflow

Run the scripts in this order.

1. Install dependencies once:

```powershell
cd honeypot/analysis
bun install
```

2. Run analysis from the repo root.
   This processes all available live data by default. Add `--from` / `--to` only when you want to limit the date range.

```powershell
python honeypot/analysis/analyze_cowrie.py analyze `
  --input-root honeypot/outputs `
  --artifact-dir honeypot/analysis/artifacts `
  --sensors baseline,hostname
```

3. Render the visualization from the previously generated graph JSON:

```powershell
python honeypot/analysis/analyze_cowrie.py render `
  --artifact-dir honeypot/analysis/artifacts
```

The `render` step reads only `cowrie_state_machine_graph.json` and does not reprocess the raw Cowrie logs.

4. Serve the generated artifacts over HTTP with Bun so the interactive HTML can load the sibling SVG:

```powershell
bun run honeypot/analysis/serve_artifacts.ts --dir honeypot/analysis/artifacts --port 3000
```

5. Open `http://localhost:3000/`.

- Hover a node to see baseline, hostname, and total session counts.
- Click a node to populate the right-hand sidebar with the top full flows through that node.
- Sidebar flow entries render one state per line, reuse the node colors, and include sample session links into Splunk.
- The selected node card also includes a direct Splunk search link for that node.

## Container workflow

Run the services in this order from `honeypot/analysis`.

This uses separate images:

- `Dockerfile.viewer` for the Bun HTTP viewer
- `Dockerfile.python` for `analyze`
- `Dockerfile.node` for `render`

1. Run analysis.
   This also processes all available live data by default. Add `--from` / `--to` only when you want a narrower window.

```powershell
cd honeypot/analysis
docker compose --profile tools run --rm analyze
```

2. Run render.
   Rebuild first if you changed any Dockerfile or JS dependency.

```powershell
cd honeypot/analysis
docker compose --profile tools build render
docker compose --profile tools run --rm render
```

3. Start the viewer.

```powershell
cd honeypot/analysis
docker compose up viewer
```

Analysis outputs:

- `cowrie_sessions.parquet` or `cowrie_sessions.csv`
- `cowrie_stage_counts.csv`
- `cowrie_fingerprinting_candidates.csv`
- `cowrie_state_machine_nodes.csv`
- `cowrie_state_machine_edges.csv`
- `cowrie_session_paths.csv`
- `cowrie_top_path_prefixes.csv`
- `cowrie_state_machine_graph.json`
- `cowrie_summary.md`

Renderer output:

- `cowrie_state_machine.svg`
- `cowrie_state_machine.html`
