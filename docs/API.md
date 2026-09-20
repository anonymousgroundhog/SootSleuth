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

### `POST /api/malware`

Synchronous static malware triage. Body: `{ jobId, file? }`. Returns the analysis
object (see [FORENSIC.md → Malware analysis](FORENSIC.md#malware-analysis)):
`{ file, sizeBytes, hashes:{md5,sha1,sha256}, meta, permSource, riskScore,
riskLevel, note, dangerousPermissions[], otherPermissions[], behaviors[],
combos[], packer:{detected,hits,notes}, iocs:{urls,domains,ips}, iocCounts, scan }`.
Read-only; nothing is executed.

### `POST /api/files`

APK file tree. Body: `{ jobId, file? }` → `{ file, entryCount, tree, bundle? }`
where `tree` is a nested array of `{ name, path, dir, children }` (dirs) and
`{ name, path, dir:false, size, kind }` (files); `kind` ∈ manifest, resources,
dex, native, image, font, signature, xml, text, binary, other.

### `POST /api/file`

One file's contents. Body: `{ jobId, file?, entry }` (`entry` = a ZIP path from
the tree). Returns `{ path, kind, size, format, … }`:
- `format:"axml"` / `"resources"` → `content` is decoded text (via aapt2/aapt).
- `format:"text"` → `content` is UTF-8 (`truncated:true` past 512 KB).
- `format:"binary"` → `hex` (first 512 bytes) + `strings` (sample).
`entry` only indexes the APK's own ZIP directory — an unknown entry yields
`{ error }`, never a filesystem read.

### `POST /api/decompile`

Decompiled Java for one class (jadx). Body: `{ jobId, file?, className }` →
`{ className, java, engine:"jadx", cached }`. Class names come from
`/api/classes`. Output is cached per job under `uploads/<jobId>/.jadx/`. If jadx
isn't installed, responds **501** `{ error, code:"NO_JADX" }`; the Jimple views
still work without it.

### `POST /api/droidlysis`

Runs **DroidLysis** over the APK and returns its extracted properties, shaped
for the Suspicious App Code tab. Body: `{ jobId, file?, refresh? }`.

Asynchronous, like the inject routes — DroidLysis unpacks and disassembles the
whole app, which is slow. Behaviour:

- Cached result available and `refresh` is falsy → **200** `{ started:false, report }`.
- Otherwise → **200** `{ jobId, started:true }` and the run streams its output
  over `/api/stream/:jobId`. The finished report arrives on the SSE `done`
  event as `{ kind:"droidlysis", ok, report?, error?, code? }`.
- DroidLysis not installed → **501** `{ error, code:"NO_DROIDLYSIS" }`.

`report` shape:

```jsonc
{
  "engine": "droidlysis",
  "reportVersion": 1,                // cache schema; older caches are re-run
  "degraded": true,                  // a CODE-ANALYSIS layer was missing
  "degradedMissing": ["apktool", "baksmali", "dex2jar"],
  "degradedSkipped": ["Smali code analysis (no disassembly)", …],
  "degradedMinor": false,            // something missing, but no layer lost
  "file":     { "name", "sizeBytes", "classes", "dirs", … },
  "manifest": { "package", "mainActivity", "permissions": [], "activities": [], … },
  "packed":   true,                  // null when `degraded` — unknown, not false
  "multidex": [],
  "strings":  { "appName", "urls": [], "phoneNumbers": [], "base64": [] },
  "kits":     [ { "name", "why" } ],           // recognised 3rd-party SDKs
  "categories": [                              // hits grouped for display
    { "name": "Evasion & anti-analysis",
      "hits": [ { "group": "smali|wide|arm", "name", "why", "pattern", "values" } ] }
  ],
  "counts":   { "total", "smali", "wide", "arm", "kits" }
}
```

Each hit's `why`/`pattern` come from DroidLysis' own `conf/*.conf` rule files,
read back at response time so a hit explains itself instead of being a bare
rule name. Results are cached per job at `uploads/<jobId>/.droidlysis/`; a
cached report whose `reportVersion` doesn't match the current schema is ignored
and the analysis re-run.

Disassembling a large multi-dex app leaves ~1 GB of Smali, extracted DEX and
unzipped resources per job, so once the report is shaped those intermediates are
deleted and only the reports are kept (`report.json`, `details.md`,
`AndroidManifest.xml` and the shaped cache — a few MB).

**`degraded` matters.** DroidLysis still produces a report when apktool /
baksmali / dex2jar are missing, but silently skips Smali disassembly and
manifest parsing — so a near-empty result means *not inspected*, not *not
suspicious*.

`degraded` is true only when a **code-analysis** layer was lost (apktool or
baksmali missing); the UI then shows a "results are not conclusive" banner and
`packed` is forced to `null`, because its "no main activity" precondition is
trivially true when the manifest was never parsed. A missing `dex2jar` alone
costs only the DEX→JAR step, so it sets `degradedMinor` and renders as a
footnote instead — keeping the loud warning meaningful.

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
