# Internals

Shared plumbing: cross-platform tool discovery, the subprocess runner, the
server's job/SSE registry, and the frontend.

---

## `lib/tools.js` — cross-platform discovery

Everything OS-specific lives here so the rest of the code is platform-agnostic.

- `which(name)` — wraps `where` (Windows) / `which` (unix).
- `findBin(name)` — PATH first (with/without `.exe`), then common install
  locations per OS (`~/.cargo/bin`, `~/.local/bin`, `/usr/local/bin`,
  `/opt/homebrew/bin`, `C:\Program Files\…`).
- `findAdb()` — searches the Android SDK roots' `platform-tools/`, then PATH.
- `findJadx()` — PATH (`jadx` / `jadx.bat`), then `JADX_HOME/bin`, then common
  install dirs (`/opt/jadx`, `~/.local/jadx`, Homebrew libexec, …). Optional; its
  absence only disables the decompiled-Java view.
- `findBuildTool(name)` — newest `build-tools/<ver>/` binary; knows `apksigner`
  is a `.bat` on Windows while `zipalign`/`aapt2` are `.exe`.
- `findAndroidPlatforms()` — first SDK root with a non-empty `platforms/`; falls
  back to a bundled MADPro platforms dir for convenience.
- `sdkRoots()` — `ANDROID_HOME`, `ANDROID_SDK_ROOT`, and the OS-default SDK
  locations.
- `jarClasspath()` — joins every jar in `jar_libs/` with the platform classpath
  separator (`CP_SEP`: `;` on Windows, `:` elsewhere).
- `checkTools()` — the snapshot behind `/api/tools`.

Constants exported for the rest of the app: `PROJECT_ROOT`, `JAR_LIBS_DIR`,
`JAVA_SRC_DIR`, `INJECTOR_CLASS`, `UPLOADS_DIR`, `OUTPUT_DIR`, plus `IS_WIN`,
`EXE`, `CP_SEP`.

---

## `lib/runner.js` — streaming subprocess runner

`run(cmd, args, opts) -> Promise<boolean>` (true on exit code 0). Spawns a
process and streams stdout/stderr **line by line** to `opts.onLine(line, stream)`
where `stream` is `"out"` | `"err"` | `"sys"`. This callback is what lets
server.js relay each line over SSE.

Options:

- `timeoutMs` — hard wall-clock kill (SIGTERM then SIGKILL).
- `stuckMs` — kill if no output for N ms (catches hung Soot runs).
- `filterSoot` — suppress Soot's GC/typing noise (`SOOT_NOISE_RE`).
- `filterRe` — suppress lines matching a custom regex.
- `cwd`.

Partial lines are buffered across `data` chunks and flushed on close.

> Note: the read-only forensic explorer (`lib/jimple.js`) uses `spawnSync`
> instead, because it returns a single JSON/text blob and is memoised — no need
> for streaming.

---

## `server.js` — app, jobs, SSE

### Upload

`multer` disk storage puts each upload under `uploads/<jobId>/` (a random
6-byte hex id), so a split set and its later injected output live together and
can be cleaned as a unit. Filenames are sanitised; a file filter enforces the
`.apk`/`.apks`/`.xapk` extensions and a 2 GB cap.

### Job registry & SSE

A `jobs` Map holds, per `jobId`:

```js
{ lines: [],        // buffered log events
  clients: Set<res>,// attached SSE responses
  done: bool }
```

- `pushLine(jobId, text, stream)` — append to the buffer **and** write to every
  attached client. Buffering means a browser that connects a moment after a job
  starts still receives every line from the beginning (`/api/stream` replays
  `lines` before going live).
- `finishJob(jobId, payload)` — emit `done` to all clients and close their
  streams.
- `writeSse(res, event, data)` — the `event: …\ndata: …\n\n` wire format.

Long-running routes (`/api/inject`, `/api/instrument`) return
`{ started: true }` immediately, then run their `lib/*` function with
`log = (line, stream) => pushLine(jobId, line, stream)`, and call `finishJob`
in `.then`/`.catch`.

### APK resolution

- `resolveApk(jobId, file)` — the uploaded file to act on (explicit `file`, else
  `base.apk`, else largest); accepts bundles.
- `resolveSootApk(jobId, file)` — for the Jimple/CFG endpoints: if the resolved
  file is a bundle, unpack it once to `uploads/<jobId>/.soot-base/` and return
  its base APK, so Soot processes a real APK, not the outer ZIP.

---

## Frontend — `public/`

Plain HTML/CSS/JS, no build step, no framework.

### `app.js`

- **Upload** — drag-drop or browse → `POST /api/upload`; opens the SSE stream.
- **SSE** — `EventSource` on `/api/stream/:jobId`; `line` events append to the
  console (colored by stream), `done` renders download links / enables the
  instrument button and reopens a fresh stream for the next action.
- **Tabs** — Forensic / Hacking panel switching.
- **Forensic** — `Run inspection` renders the scan cards; the **explorer**
  loads classes, then methods, and shows Jimple text or the CFG.
- **CFG renderer** — `renderCfg()` builds the SVG graph client-side (layered
  layout, colored/kinded edges, back-edges routed as dashed curves). Detailed in
  [FORENSIC.md → The frontend](FORENSIC.md#the-frontend-in-publicappjs).
- **Hacking** — scope radios (all vs custom filter), `Inject logs`
  (`POST /api/inject`), `Install & capture logcat` (`POST /api/instrument`).

### `index.html` / `style.css`

Drop zone, tool chips, two tabs, the explorer's three-column layout, and the
live console. Dark theme via CSS custom properties; the class/method lists and
Jimple/CFG panes are scroll containers so nothing overflows the page.

---

## Building the Java helpers

You don't build them by hand — `lib/injector.js` (`ensureCompiled`) and
`lib/jimple.js` (`ensureCompiled`) each `javac` their sources against
`jarClasspath()` into `java/` whenever the `.class` is missing or older than the
`.java`. The compiled `.class` files are gitignored.

To compile manually for debugging:

```bash
# unix
javac -cp "$(ls jar_libs/*.jar | tr '\n' ':')" -d java java/*.java
# windows (PowerShell)
javac -cp "$((Get-ChildItem jar_libs\*.jar).FullName -join ';')" -d java java\*.java
```
