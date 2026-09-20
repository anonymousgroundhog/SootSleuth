# HTTP API

All endpoints are served by `server.js`. Request bodies are JSON
(`Content-Type: application/json`) unless noted. Most POSTs identify the APK by
`jobId` (from `/api/upload`) plus an optional `file` name; when `file` is
omitted the server picks `base.apk` if present, else the largest uploaded file
(`resolveApk`).

## `GET /api/tools`

Tool/SDK availability on the host + connected devices. Used to render the status
chips and populate the device picker.

```jsonc
{
  "tools": {
    "platform": "linux",
    "java": true, "javac": true, "adb": true,
    "aapt2": true, "zipalign": true, "apksigner": true,
    "unzip": true, "strings": true,
    "platforms": true, "platformsPath": "/home/.../Sdk/platforms",
    "injectorCompiled": true, "jarLibsExist": true
  },
  "devices": [ { "serial": "ZT4229DSNS", "state": "device" } ]
}
```

## `POST /api/upload`

`multipart/form-data`, field `apk` (repeatable, up to 12 files — for split sets).
Accepts `.apk` / `.apks` / `.xapk`, 2 GB max. Stores files under
`uploads/<jobId>/`.

```jsonc
// response
{ "jobId": "03cf19d39327",
  "files": [ { "name": "base.apk", "size": 41231234, "path": "..." } ],
  "primary": "base.apk",
  "dir": "/abs/uploads/03cf19d39327" }
```

---

## Forensic

### `POST /api/inspect`

Synchronous static scan. Body: `{ jobId, file? }`. Returns the inspection object
(see [FORENSIC.md → Result shape](FORENSIC.md#result-shape)).

### `POST /api/classes`

Body: `{ jobId, file? }` → `{ classes: string[] }` — the app's own class names,
sorted. First call for a given APK is slow (Soot startup); memoised after.
Bundles are resolved to their base APK automatically.

### `POST /api/methods`

Body: `{ jobId, file?, className }` →
`{ className, methods: [ { subsig, name } ] }`.

### `POST /api/jimple`

Body: `{ jobId, file?, className, subsig? }` →
`{ className, subsig, jimple: "<text>" }`. Whole class when `subsig` is omitted,
else that one method.

### `POST /api/cfg`

Body: `{ jobId, file?, className, subsig }` → the control-flow graph JSON:
`{ method, nodes: [ { id, text, kind } ], edges: [ { from, to, kind } ] }`.
Edge kinds: `branch` / `fall` / `goto` / `switch` / `exc`. (See
[FORENSIC.md → CFG construction](FORENSIC.md#cfg-construction).)

### `POST /api/callgraph`

Whole-app call graph — methods as nodes, "calls" as edges. Body:
`{ jobId, file?, pkgPrefix?, maxNodes? }`.

- `pkgPrefix` — scope to this package. Omit/blank → the app's auto-detected base
  package.
- `maxNodes` — cap (default 400); the graph is truncated to keep it renderable.

Response:

```jsonc
{ "scope": "com.app.aiimglarger", "basePackage": "com.app.aiimglarger",
  "nodeCount": 400, "edgeCount": 322, "truncated": true, "maxNodes": 400,
  "entryPoints": [1, 5, 87], "primaryEntry": 5,
  "nodes": [ { "id": 5, "label": "AiEnlargerApp.onCreate", "cls": "...", "sub": "...",
               "kind": "method", "entry": true, "entryKind": "application", "primary": true } ],
  "edges": [ { "from": 5, "to": 42 } ] }
```

Node `kind` ∈ `init` / `static` / `method`. **Entry points** (Android lifecycle
roots) carry `entry: true`, an `entryKind`
(`application`/`activity`/`service`/`receiver`/`provider`/`main`), and `primary`
for the app's starting point; the top level lists `entryPoints` (ids) and
`primaryEntry` (id, or `-1`). See
[FORENSIC.md → Whole-app call graph](FORENSIC.md#3-whole-app-call-graph).

---

## Hacking (async + SSE)

### `POST /api/inject`

Body: `{ jobId, file?, injectAll = true, patterns = [] }`. Returns
`{ started: true, outputDir }` immediately and streams progress over the job's
SSE channel. `patterns` (class-filter globs) apply only when `injectAll` is
false. On completion the `done` event carries
`{ kind: "inject", ok, apks: [...], bundle? }`.

### `POST /api/instrument`

Body: `{ jobId, device?, durationMs = 30000 }`. Installs the injected output on
`device` (or the first connected device), launches it, and captures logcat for
`durationMs`. Requires a prior successful `/api/inject`. Streams over SSE; `done`
carries `{ kind: "instrument", ok, pkg }`.

### `GET /api/stream/:jobId`

Server-Sent Events for a job. Replays all buffered lines, then streams live
ones. Events:

- `line` — `{ text, stream, t }` where `stream ∈ { "out", "err", "sys" }`.
- `done` — the job's completion payload; the server then closes the stream.

### `GET /api/download/:jobId/:name`

Downloads a produced file from `output/<jobId>/` (injected APK or bundle).

---

## Errors

Endpoints return `4xx`/`5xx` with `{ "error": "<message>" }`. Async endpoints
report failures **inside the stream** (an `err` line + a `done` payload with
`ok: false`) since they've already returned `200 { started: true }`.
