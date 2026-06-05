# Cowrie analysis

Install the renderer dependency once:

```powershell
cd honeypot/analysis
npm install
```

Run analysis from the repo root:

```powershell
python honeypot/analysis/analyze_cowrie.py analyze `
  --input-root honeypot/outputs `
  --artifact-dir honeypot/analysis/artifacts `
  --from 2026-05-30 `
  --to 2026-06-04 `
  --sensors baseline,hostname
```

Render the visualization from the previously generated graph JSON:

```powershell
python honeypot/analysis/analyze_cowrie.py render `
  --artifact-dir honeypot/analysis/artifacts
```

The `render` step reads only `cowrie_state_machine_graph.json` and does not reprocess the raw Cowrie logs.

Serve the generated artifacts over HTTP with Bun so the interactive HTML can load the sibling SVG:

```powershell
bun run honeypot/analysis/serve_artifacts.ts --dir honeypot/analysis/artifacts --port 3000
```

Then open `http://localhost:3000/`.

- Hover a node to see baseline, hostname, and total session counts.
- Click a node to populate the right-hand sidebar with the top full flows through that node.
- Sidebar flow entries render one state per line, reuse the node colors, and include sample session links into Splunk.
- The selected node card also includes a direct Splunk search link for that node.

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
