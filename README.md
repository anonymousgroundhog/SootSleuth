# SootSleuth

Web tool for Android APK **forensics** and **Soot-powered log injection**.
Drag an APK into the browser and either investigate it or instrument it.

## Modes

- **🕵️ Forensic** — static inspection: ad-SDK detection (AdMob, AppLovin,
  Unity, IronSource, Meta, and more), Play Store / billing traces, package
  metadata, DEX count. Also a **Jimple & control-flow explorer**: pick an app
  class → a method → view Soot's Jimple IR or an interactive control-flow graph
  (statements as nodes; branch / fall-through / goto / switch / exception edges
  color-coded). Read-only.
- **💉 Hacking** — inject `Log.d("SootInjection", "Entering: <method sig>")` at
  the start of every targeted method via Soot (`LogInjector.java`), then
  zipalign + apksign the result. Optionally install the injected APK on a
  connected device/emulator and capture logcat live.

## Documentation

The README is the overview. Detailed, code-level docs live in [`docs/`](docs/):

| Doc | Covers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the pieces fit; request flow; sync vs async+SSE; directory layout; design choices |
| [docs/FORENSIC.md](docs/FORENSIC.md) | The static scan (`inspector.js`) and the Jimple/CFG explorer (`jimple.js` + `JimpleDumper.java`) |
| [docs/INJECTION.md](docs/INJECTION.md) | The full inject pipeline: `LogInjector` → `DexSplicer` (VerifyError fix) → signing → XAPK bundles → on-device instrument |
| [docs/API.md](docs/API.md) | Every HTTP endpoint with request/response shapes |
| [docs/INTERNALS.md](docs/INTERNALS.md) | Cross-platform tool discovery, the subprocess runner, the job/SSE registry, the frontend, building the Java helpers |

## Requirements

| Feature | Needs |
|---|---|
| Server + forensic scan | Node.js 18+, a JDK (for full injection) |
| Injection | JDK, Android platform JARs (`ANDROID_HOME`) |
| Signing | `zipalign` + `apksigner` (Android build-tools) |
| Instrumentation | `adb` + a connected device/emulator |
| Package metadata | `aapt2` (build-tools) — optional |

Tool availability is shown as chips in the UI; missing tools degrade
gracefully (e.g. forensic scan falls back to a pure-JS ZIP reader when `unzip`
is absent, so it works on Windows too).

Cross-platform: Windows, macOS, Linux (paths, classpath separators, and
build-tool extensions are handled per-OS in `lib/tools.js`).

## Run

```bash
npm install
npm start            # http://localhost:4700  (override with PORT=xxxx)
```

Then open the URL, drag an APK onto the drop zone, pick a mode.

## Injection scope & AdMob

`LogInjector` keeps a hard **exclude list** (framework, GMS, ads, protobuf,
kotlin runtime, …) that applies even under *Inject all methods* — those
packages are skipped to avoid ART `VerifyError`s.

To deliberately instrument **AdMob** classes, choose **Custom class filter** and
enter a pattern such as:

```
com.google.android.gms.ads.*
```

A custom filter runs in non-inject-all mode and bypasses the exclude list, so
the targeted classes are instrumented.

## XAPK / split bundles

`.xapk` and `.apks` files are ZIP bundles (base APK + `config.*` splits +
`manifest.json`) and are handled in both modes: forensic inspects the inner
base APK; hacking injects the base, re-signs the base + every split with one
key, and repacks a complete injected bundle. Full detail:
[docs/INJECTION.md → XAPK / split bundles](docs/INJECTION.md#xapk--split-bundles-libbundlejs).

## Dex splicing (avoids VerifyError on modern apps)

Soot 4.7.1's DEX backend re-encodes **every** class it round-trips through
Jimple, corrupting some synthetic classes it never needed to touch (protobuf,
kotlinx coroutines, Room, some Compose interfaces) — ART then rejects them with
`VerifyError` / `IncompatibleClassChangeError`. SootSleuth fixes this by taking
only the injected classes from Soot's output and copying every untouched
`classes*.dex` byte-for-byte from the original APK (`java/DexSplicer.java`).
Full detail:
[docs/INJECTION.md → Dex splice](docs/INJECTION.md#step-2--dex-splice-javadexsplicerjava).

## Layout

```
server.js          Express server, upload, SSE job streaming
lib/tools.js       Cross-platform tool/SDK detection
lib/inspector.js   Forensic static analysis (unzip+strings or pure-JS)
lib/jimple.js      Forensic Jimple IR + CFG (wraps JimpleDumper.java)
lib/injector.js    Compile LogInjector → Soot inject → zipalign/apksign
lib/instrument.js  adb install → launch → logcat capture → uninstall
lib/runner.js      Subprocess spawner streaming lines to a callback
public/            Drag-drop web UI (index.html, app.js, style.css)
java/              LogInjector.java (BodyTransformer), DexSplicer.java,
                   JimpleDumper.java (Jimple/CFG dump) + compiled .class
jar_libs/          Soot 4.7.1 + dependencies
```

## Notes

- Uploads land in `uploads/<jobId>/`; injected output in `output/<jobId>/`.
  Both are gitignored and can be deleted freely.
- The injected APK is signed with a debug keystore
  (`~/.android/debug.keystore`, auto-generated) so it installs on dev devices.
