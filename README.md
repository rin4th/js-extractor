# JS Recon Lab

A client-side JavaScript bundle analyzer for authorized bug-bounty reconnaissance and security audits. Paste JavaScript source directly into the editor to beautify and statically analyze it for endpoint-like strings, sensitive keywords, Ajax/fetch/XHR calls and payload keys, security-relevant function names, and potential DOM XSS behavior.

Pasted JavaScript is analyzed locally in a browser Web Worker and is never executed or uploaded by the application.

## Run locally with Bun

```bash
bun install
bun run dev
```

Open `http://localhost:5173`.

Paste the contents of a JavaScript file into the source editor, then select **Beautify & Analyze** to view the extracted findings and beautified source.

Useful commands:

```bash
bun test
bun run build
bun run preview
```

## Run with Docker

```bash
docker build -t js-recon-lab .
docker run --rm -p 8080:80 js-recon-lab
```

Open `http://localhost:8080`.

The image uses `oven/bun:1-alpine` to perform the locked dependency install and Vite build, then copies only the static `dist` output into `nginx:alpine`.

## Analysis coverage

- Absolute URLs, relative paths, API routes, and `.asp`, `.aspx`, `.ashx`, `.php`, `.jsp`, and `.cgi` targets
- `api_key`, `token`, `secret`, `admin`, `password`, `bearer`, and `auth` variables, properties, and strings
- `fetch()`, `$.ajax()` / `jQuery.ajax()`, and `XMLHttpRequest` methods, URLs, query keys, object-body keys, and `FormData` fields
- Expandable function declarations, methods, and assigned functions containing `upload`, `delete`, `rename`, `admin`, `execute`, or `create`
- Potential DOM XSS findings that help identify code paths where attacker-controlled browser data may reach dangerous DOM or JavaScript operations
- Acorn AST parsing with regex fallbacks for malformed or unsupported JavaScript

The results are heuristic static-analysis leads, not confirmed vulnerabilities. Potential DOM XSS findings can include false positives and must be manually validated in the target application's context. Dynamic URLs, runtime-decrypted strings, computed property names, sanitization, and deeply transformed data may also require manual review. Use the tool only on assets you own or are explicitly authorized to assess.
