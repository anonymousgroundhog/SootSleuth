# Forensic mode

Read-only inspection of an APK. Two features:

1. **Static scan** — ad SDKs, Play Store traces, permissions, package metadata
   (`lib/inspector.js`).
2. **Jimple & control-flow explorer** — decompile app classes to Soot's Jimple
   IR and view a method's control-flow graph (`lib/jimple.js` +
   `java/JimpleDumper.java`).

Neither feature modifies the APK.

---

## 1. Static scan — `lib/inspector.js`

Entry point: `inspectApk(outerPath)`. Returns a plain object the UI renders as
cards. The scan layers several cheap signals rather than fully parsing the DEX.

### Bundle resolution

`resolveBundle(apkPath)` detects an `.xapk`/`.apks` bundle (a ZIP of `.apk`
files). If found it:

- reads `manifest.json` (APKPure XAPK) for package/version/permissions,
- picks the base APK (manifest's `base` entry → `base.apk` → package-named apk →
  largest inner apk),
- extracts that base APK to a temp dir and inspects **it**, while keeping the
  outer file's name/size for display.

For a plain `.apk` it returns `null` and the file is inspected directly. The
temp dir is always cleaned up in a `finally`.

### The three scan layers

`inspectSingleApk()` accumulates findings into three sets:

- **Layer 1 — ZIP entry listing.** Matches entry paths against
  `METAINF_AD_PATTERNS` (e.g. `META-INF/…applovin/mediation…`) and
  `ASSET_AD_PATTERNS` (e.g. `assets/audience_network.dex`). Cheap: needs only the
  central directory.
- **Layer 2 — DEX string scan.** For each `classes*.dex`, extract it and run a
  `strings`-style scan, then match `DEX_AD_PATTERNS` (e.g. `Lcom/google/android/gms/ads`)
  and `DEX_PLAY_PATTERNS` (e.g. `Lcom/android/vending`). This is what detects the
  ad SDK families and Play Billing/Install-Referrer/Play-API usage.
- **Layer 3 — permissions + manifest.** Permissions come from the most reliable
  available source, in order:
  1. `aapt2 dump permissions` (accurate),
  2. the XAPK `manifest.json` permission list,
  3. a best-effort `strings` scan of `AndroidManifest.xml`.

  Because a binary `AndroidManifest.xml` (AXML) yields nothing under `strings`,
  `aapt2` is effectively required for a real permission list on a plain APK.
  The chosen source is reported back as `permSource`.

Package metadata (`meta`) comes from `aapt2 dump badging`, falling back to XAPK
`manifest.json` fields.

### Cross-platform ZIP/strings

The module prefers the `unzip` and `strings` binaries when present, and
otherwise falls back to:

- `readCentralDir()` — a pure-JS ZIP central-directory reader (STORE + DEFLATE,
  the only methods APKs use),
- `stringsJS()` — runs of ≥ 4 printable ASCII characters.

So the scan works on Windows with no unix tooling. The `method` field in the
result records which path was taken (`"unzip+strings"` vs `"pure-js"`, plus
`" (bundle→base apk)"` when a bundle was unwrapped).

### Result shape

```jsonc
{
  "file": "app.xapk", "sizeBytes": 41231234,
  "bundle": { "type": "xapk", "baseApk": "com.app.apk", "splitCount": 21 },
  "meta": { "package": "...", "versionName": "...", "targetSdk": "34", ... },
  "dexCount": 4, "entryCount": 1873,
  "hasAds": true,  "adSdks": ["Google AdMob", ...],
  "hasPlayStoreTraces": true, "playStoreTraces": ["Google Play Billing", ...],
  "permissions": ["android.permission.INTERNET", ...],
  "permSource": "aapt2",
  "method": "unzip+strings (bundle→base apk)"
}
```

---

## 2. Jimple & control-flow explorer

Soot lifts Dalvik bytecode into **Jimple**, a typed three-address IR that is far
easier to read than smali. The explorer exposes that IR and the per-method
control-flow graph for the app's own classes.

### `java/JimpleDumper.java`

A single Soot program with four modes, all read-only
(`output_format_none` — Soot loads the APK but never writes it back):

| Mode | Args | Output |
|---|---|---|
| `--classes` | `<platforms> <apk>` | one **application** class name per line, sorted |
| `--methods` | `… <class>` | one method per line: `<subsignature>\t<name>` |
| `--jimple` | `… <class> [subsig]` | Jimple source: whole class, or one method |
| `--cfg` | `… <class> <subsig>` | control-flow graph as JSON |

Soot is configured like the injector (phantom refs, no full resolver, single
thread, ignore resolution errors) so obfuscated apps load without aborting.
Method bodies are retrieved defensively — `abstract`/`native`/unresolvable
methods yield a `// no body` note rather than an exception.

**Method subsignatures** (e.g. `void onCreate()`, `java.lang.String decrypt(java.lang.String)`)
are Soot's unique-within-a-class method identifier and are what the UI passes
back to select a method.

### CFG construction

`--cfg` builds an **`ExceptionalUnitGraph`** (not `BriefUnitGraph`) so that
exception-handler edges — `try` block → `catch` handler — appear in the graph.
Without this, catch blocks show up as unreachable islands. Each Jimple unit
becomes a node (id = its index in the unit chain); each graph successor becomes
an edge with a classified **kind**:

- `branch` — the taken target of an `if`
- `fall` — fall-through to the next unit (also the not-taken side of an `if`)
- `goto` — unconditional jump
- `switch` — a `switch` successor
- `exc` — anything else non-adjacent, i.e. an exception edge

Node kinds (`branch`/`switch`/`goto`/`throw`/`return`/`stmt`) let the UI color
boxes. Output is compact JSON:

```jsonc
{ "method": "java.lang.String decryptParams(java.lang.String)",
  "nodes": [ { "id": 0, "text": "this := @this: ...", "kind": "stmt" }, ... ],
  "edges": [ { "from": 0, "to": 1, "kind": "fall" }, ... ] }
```

JSON is hand-serialised with a minimal escaper so the tool needs no JSON
library on the classpath.

### `lib/jimple.js` — the Node wrapper

- `ensureCompiled()` — recompiles `JimpleDumper.java` when the `.class` is
  missing or older than the source.
- `runDumper(apk, mode, extra)` — one `java JimpleDumper …` run (`spawnSync`,
  `-Xmx4g`, 5-minute timeout, 128 MB stdout buffer). Soot's stderr noise is
  discarded; a non-zero exit surfaces the `ERROR:` line (e.g. "class not found").
- `listClasses` / `listMethods` / `jimple` / `cfg` — thin wrappers, each
  **memoised** per `(apk, mode, args)` in a `Map` for the process lifetime.
  This matters: Soot's startup dominates each call, so the first request for a
  given APK is slow (tens of seconds on a large app) and every later one is
  instant.

### Bundles

The server resolves an `.xapk`/`.apks` job to its base APK once
(`resolveSootApk` in `server.js` unpacks to `uploads/<jobId>/.soot-base/` and
reuses it), so the explorer inspects the real base APK, not the outer ZIP.

### The frontend (in `public/app.js`)

- **Class list** (left) and **method list** (middle), each with a text filter.
- **View pane** (right) toggles between **Jimple** text and the **Control flow**
  graph.
- `renderCfg(cfg)` draws the graph as an **SVG** with no external library:
  - assigns each node a depth by longest-path relaxation over the edges (capped
    to survive cycles/back-edges),
  - lays depths out top→bottom into rows,
  - draws statement boxes and cubic-Bézier edges, routing back-edges out to the
    right as dashed curves,
  - colors edges by kind and adds per-color arrowhead markers + a legend.

It's a pragmatic layered layout — good enough for method-sized graphs and fully
self-contained.
