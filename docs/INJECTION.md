# Hacking mode — the injection pipeline

Injects `Log.d("SootInjection", "Entering: <method sig>")` at the entry of
targeted methods, produces a **signed, installable** APK (or XAPK bundle), and
optionally installs it on a device and captures the resulting logcat.

The hard part isn't inserting the log call — it's shipping an APK that modern
Android's verifier will still accept. That's what the **dex splice** step is for.

Files involved: `lib/injector.js` (orchestration), `java/LogInjector.java`
(the Soot transform), `java/DexSplicer.java` (the fix), `lib/bundle.js`
(XAPK handling), `lib/instrument.js` (on-device run).

---

## Pipeline overview

```
                 plain .apk                         .xapk / .apks
                     │                                    │
             ┌───────▼────────┐                  ┌────────▼─────────┐
             │  injectSingle  │                  │   injectBundle    │
             └───────┬────────┘                  └────────┬─────────┘
                     │                          unpack bundle (all apks)
        1. runSoot (LogInjector)                          │
        2. spliceDex (DexSplicer)          inject + splice the BASE apk only
        3. signApks (zipalign+apksigner)   re-sign base + every split (1 key)
                     │                          repack → <name>-injected.xapk
              signed injected .apk                       │
                                                  signed injected bundle
```

---

## Step 1 — Soot injection: `java/LogInjector.java`

A Soot `BodyTransformer` registered in the `jtp` (Jimple transformation) pack.
For every non-abstract, non-native method body it inserts a single Jimple
statement calling `android.util.Log.d(tag, "Entering: <signature>")`.

### Where the log call goes

`injectLog(body)` finds a safe insertion point:

- skips leading `IdentityStmt`s (the `this`/parameter bindings),
- in constructors, skips past the `super(...)` / `this(...)` call
  (`SpecialInvokeExpr`) so the object is initialised first,
- inserts before the first "real" statement, or before the `return` if the body
  is otherwise empty.

### Modes

Invoked as:

```
java LogInjector [--inject-all] <android-platforms> <apk> <output-dir> [class-filter-csv]
java LogInjector --list-classes  <android-platforms> <apk>
```

- **`--inject-all`** — instrument every method (subject to the exclude list
  below).
- **class-filter-csv** — a comma-separated list of wildcard patterns
  (e.g. `com.google.android.gms.ads.*`). Only matching classes are instrumented,
  and this mode **bypasses the exclude list**, which is how you deliberately hit
  AdMob classes.

### The exclude list (why AdMob is skipped by default)

Even under `--inject-all`, `LogInjector` refuses to touch a hard-coded set of
packages: the Java/Android runtime, Kotlin/Kotlinx, protobuf,
Firebase/GMS/Google ads, and a few libraries with known enum-`<clinit>`
issues. Soot's DEX backend corrupts certain synthetic/enum classes during
rewrite, and ART then rejects them at runtime. Excluding these packages keeps
Soot from loading their bodies at all. To instrument AdMob on purpose, use a
**custom class filter** (non-inject-all mode), which bypasses the list.

### Soot configuration for scale & robustness

`setupSoot()` sets: phantom refs on, no full resolver, `no_bodies_for_excluded`,
`ignore_resolution_errors`, single-threaded (avoids `ConcurrentModificationException`
on the unit chain), and DEX output. Each method transform is wrapped in
try/catch so one bad obfuscated body increments a `skipped` counter instead of
aborting the whole APK.

### The injected-classes list

As it injects, `LogInjector` records each class it actually modified and writes
`<output-dir>/injected-classes.txt`. **This file is the contract with the dex
splicer** (step 2): it says exactly which classes changed.

### Heap

Inject-all loads every method body of the whole app, so large APKs blow past a
small heap. `lib/injector.js` runs Soot with `-Xmx8g` for inject-all (`-Xmx4g`
for a narrow filter), overridable via `SOOTSLEUTH_HEAP`, plus
`-XX:+ExitOnOutOfMemoryError` and a watcher that turns an OOM into an actionable
error message instead of a silent empty output.

---

## Step 2 — Dex splice: `java/DexSplicer.java`

**The problem.** Soot 4.7.1's DEX backend round-trips *every* class through
Jimple and re-encodes it. That re-encoding corrupts some synthetic classes it
never needed to touch — protobuf `GeneratedMessageLite$MethodToInvoke`, kotlinx
coroutines `SharedFlowImpl`, Room DAO impls, some Compose interfaces. ART then
rejects them at runtime with `VerifyError` / `IncompatibleClassChangeError`,
even though those classes were never targeted.

**The fix.** Take from Soot's output only the classes we actually injected;
take everything else from the **original** APK, unchanged.

`DexSplicer` (using dexlib2) does this per-dex-file:

```
java DexSplicer <original-apk> <injected-apk> <output-apk> <injected-classes.txt>
```

1. Read the injected class names → dex type descriptors (`com.a.B` → `Lcom/a/B;`).
2. Determine the original APK's own dex **opcode set** and use it for all reads
   and writes, so encoding matches the original exactly (a mismatched opcode set
   can mis-encode interface dispatch → `IncompatibleClassChangeError`).
3. Load the injected `ClassDef`s for exactly the listed classes from Soot's
   output.
4. For each original `classes*.dex`:
   - **contains no injected class** → copy that dex **byte-for-byte** from the
     original APK (`extractZipEntry`),
   - **contains ≥ 1 injected class** → rebuild only that dex via a `DexPool`,
     swapping the injected `ClassDef` in place and keeping every sibling class as
     it was.
   Injected classes stay in their original dex entry, so there are never
   duplicate class definitions across dex files.
5. `rebuildApk()` copies the original APK entry-for-entry (resources, libs,
   assets), dropping the old `classes*.dex` and the stale signature files, and
   adds the merged dex set.

**Result:** injected classes carry the log calls; every other class is
bit-identical to the original → no `VerifyError`. Verified on a modern
Compose/coroutines/datastore app (AI Enlarger): 19 → 0 `VerifyError`, 2 → 0
`FATAL`, 4 → 0 `IncompatibleClassChangeError`.

If the injected-classes list is missing or the splice fails, `lib/injector.js`
logs a warning and falls back to Soot's raw output (which may `VerifyError` on
modern apps).

---

## Step 3 — Signing: `signApks()` in `lib/injector.js`

Each output `.apk` is `zipalign`ed then signed with `apksigner` using the debug
keystore (`~/.android/debug.keystore`, auto-generated with `keytool` if absent).
If `zipalign`/`apksigner` aren't found, the APK is left unsigned with a clear
warning (it won't install as-is).

For a **bundle**, the injected base **and every split** are signed with the
*same* key — Android requires a uniform signer across a split set.

---

## XAPK / split bundles: `lib/bundle.js`

An `.xapk`/`.apks` is a plain ZIP of `base.apk` + `config.*` split APKs +
`manifest.json`. `injectBundle()`:

1. **unpacks** the bundle (`unzip` CLI, or a pure-JS STORE+DEFLATE reader),
2. finds the base APK (`findBaseApk`: manifest `base` entry → `base.apk` →
   package-named → first non-`config.*`),
3. injects + dex-splices **only the base**, placing the spliced base over the
   unpacked base (keeping its filename),
4. **re-signs** the base + all splits with one debug key,
5. **repacks** (`zip -0 -j -X` CLI, or a pure-JS CRC32 STORE writer) into
   `<name>-injected.xapk` — injected base + all splits + `manifest.json` + icon —
   dropping signing scratch files (`*-aligned.apk`, `*.idsig`).

The whole bundle is what you download, so it installs as a complete app. The
pure-JS ZIP reader/writer means bundle handling also works on Windows without
Info-ZIP binaries.

---

## On-device run: `lib/instrument.js`

`instrument({ apkDir, device, durationMs })`:

1. Resolves the output APK set — loose `.apk`(s), or unpacks an injected
   `.xapk`/`.apks` to a temp dir for `install-multiple`.
2. Picks the base APK (`base.apk` → first non-split → largest) and reads its
   package name via `aapt2 dump badging`.
3. Uninstalls any existing copy (avoids signature mismatch), clears logcat.
4. Installs: `adb install-multiple -r -t -g` for a split set, else `adb install`.
   `-g` grants runtime permissions.
5. Launches via `monkey -c android.intent.category.LAUNCHER 1`.
6. Streams logcat for `durationMs`, scoped to the app's PID when resolvable
   (else filtered to `SootInjection:D`), pushing each line to the UI.
7. Uninstalls and cleans up the temp dir.

Every step streams through the same `log(line, stream)` callback the inject
pipeline uses, so instrumentation output appears live in the same console.
