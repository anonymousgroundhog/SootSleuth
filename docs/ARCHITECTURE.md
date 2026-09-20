# Architecture

How SootSleuth is put together and how a request flows through it.

## Big picture

SootSleuth is a small Node/Express server that drives a set of command-line
tools — Soot (via three helper Java programs), the Android build-tools
(`aapt2`, `zipalign`, `apksigner`), and `adb`. The browser is a thin client:
it uploads an APK, then calls JSON endpoints that either return a result inline
(fast, synchronous) or start a background job that streams its output over
Server-Sent Events (SSE).

```
┌── browser (public/) ─────────────┐
│  drag-drop upload                 │
│  Forensic tab / Hacking tab       │
│  live console (SSE)               │
└───────────┬──────────────────────┘
            │ HTTP + SSE
┌───────────▼── server.js ─────────┐
│  upload (multer)                  │
│  job registry + SSE fan-out       │
│  route → lib/*                    │
└───┬───────┬───────┬───────┬───────┘
    │       │       │       │
 inspector jimple injector instrument
    │       │       │       │
    │    JimpleDumper LogInjector  adb
    │       │      +DexSplicer      │
  aapt2   Soot     Soot+dexlib2  device
  strings          zipalign/apksigner
```

## The two modes

| Mode | Endpoints | Backing code | Writes the APK? |
|---|---|---|---|
| **Forensic** | `/api/inspect`, `/api/files`, `/api/file`, `/api/classes`, `/api/methods`, `/api/jimple`, `/api/cfg`, `/api/callgraph` | `lib/inspector.js`, `lib/files.js`, `lib/jimple.js` + `java/JimpleDumper.java` | No — read-only |
| **Malware analysis** | `/api/malware`, `/api/decompile` (+ `/api/classes` for the picker) | `lib/malware.js`, `lib/decompile.js` (jadx) | No — read-only |
| **Hacking** | `/api/inject`, `/api/instrument` | `lib/injector.js` + `java/LogInjector.java` + `java/DexSplicer.java`, `lib/instrument.js` | Yes — produces a signed injected APK/bundle |

## Two response styles

1. **Synchronous JSON** — `/api/inspect` and the Jimple/CFG endpoints return the
   full result in the HTTP response. They're fast enough (inspection is seconds;
   a Jimple/CFG call is one short Soot run, memoised after the first).

2. **Async job + SSE** — `/api/inject` and `/api/instrument` can run for minutes
   and produce lots of progress output. They return immediately with
   `{ started: true }`, do the work in the background, and push every log line to
   the browser over `/api/stream/:jobId`. See
   [INTERNALS.md → Job registry & SSE](INTERNALS.md#job-registry--sse).

## A request end-to-end (inject example)

1. Browser POSTs the APK to `/api/upload`; multer stores it under
   `uploads/<jobId>/` and returns the `jobId`.
2. Browser opens `EventSource("/api/stream/<jobId>")`.
3. Browser POSTs `/api/inject { jobId, injectAll, patterns }`. Server resolves
   the APK path, returns `{ started: true }`, and kicks off `inject()`.
4. `inject()` compiles the Java helpers if stale, runs Soot's `LogInjector`,
   splices the injected classes back onto the original dex with `DexSplicer`,
   then `zipalign` + `apksigner`. Each step's stdout/stderr is streamed line by
   line through a `log(line, stream)` callback → `pushLine()` → every attached
   SSE client.
5. On completion the server emits a `done` event with the output file list; the
   browser renders download links and enables **Install & capture logcat**.

## Directory layout

```
server.js          Express app: upload, routing, job/SSE registry
lib/
  tools.js         Cross-platform binary/SDK discovery + constants
  runner.js        Subprocess spawner streaming stdout/stderr line-by-line
  inspector.js     Forensic static analysis (ad SDKs, perms, metadata)
                   + shared ZIP/strings/aapt helpers reused by files/malware
  files.js         Forensic APK file browser (tree + AXML/arsc/text/hex reads)
  malware.js       Malware triage (hashes, perms, behavior sigs, IOCs, score)
  decompile.js     Malware decompiled-Java view (jadx --single-class, cached)
  jimple.js        Forensic Jimple IR + CFG (wraps JimpleDumper.java)
  injector.js      Inject pipeline: compile → Soot → dex-splice → sign
  bundle.js        XAPK/.apks unpack + repack (CLI or pure-JS)
  instrument.js    adb install → launch → logcat → uninstall
java/
  LogInjector.java Soot BodyTransformer that inserts Log.d at method entry
  DexSplicer.java  dexlib2 splice: keep untouched dex byte-for-byte
  JimpleDumper.java Read-only Jimple/CFG dumper for the forensic explorer
public/
  index.html       Drop zone, two tabs, explorer, console
  app.js           Upload, SSE, forensic explorer + SVG CFG renderer
  style.css        Dark UI theme
jar_libs/          Soot 4.7.1, dexlib2, ASM, Guava, protobuf, … (classpath)
uploads/           Per-job uploaded APKs (gitignored)
output/            Per-job injected output (gitignored)
```

## Design choices worth knowing

- **No heavy Node deps.** Only `express` + `multer`. ZIP reading/writing,
  `strings`, and CFG layout are implemented in-repo so the tool still runs when
  unix utilities are missing (Windows).
- **Soot startup is the cost.** Every Java-helper invocation pays Soot's
  class-loading tax. The forensic explorer therefore memoises results per
  `(apk, mode, args)` for the process lifetime (`lib/jimple.js`).
- **Graceful degradation.** Missing tools disable features instead of crashing —
  the UI shows availability as chips (`/api/tools`). Forensic scan falls back
  from `unzip`/`strings` to pure-JS; signing warns and leaves the APK unsigned
  if build-tools are absent.

## Where to read next

- [FORENSIC.md](FORENSIC.md) — inspection + the Jimple/CFG explorer.
- [INJECTION.md](INJECTION.md) — the full log-injection pipeline and why it
  avoids `VerifyError`.
- [API.md](API.md) — every HTTP endpoint with request/response shapes.
- [INTERNALS.md](INTERNALS.md) — cross-platform detection, the subprocess
  runner, the job/SSE registry, and the frontend.
