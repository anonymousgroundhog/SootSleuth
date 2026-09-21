# SootSleuth

Web tool for Android APK **forensics** and **Soot-powered log injection**.
Drag an APK into the browser and either investigate it or instrument it.

## Modes

- **🕵️ Forensic** — static inspection: ad-SDK detection (AdMob, AppLovin,
  Unity, IronSource, Meta, and more), Play Store / billing traces, package
  metadata, DEX count. Also a **Jimple & control-flow explorer**: pick an app
  class → a method → view Soot's Jimple IR or an interactive control-flow graph
  (statements as nodes; branch / fall-through / goto / switch / exception edges
  color-coded), plus a **whole-app call graph** (methods as nodes, calls as
  edges; auto-scoped to the app's package, pan/zoom, click a node to jump to its
  Jimple). The call graph **identifies the app's entry points** — Android
  lifecycle roots (`Application`/`Activity`/`Service`/…) — and highlights the
  primary starting point, auto-centering the view on it. Also an **APK file
  browser**: an expandable tree of every original file packed in the APK, with a
  viewer that decodes the binary `AndroidManifest.xml` and `res/*.xml` (AXML) and
  `resources.arsc` to readable text, shows text files inline, and renders
  binaries (`.so`/`.dex`/images/fonts) as a hex head + printable strings.
  Read-only.
- **🦠 Malware analysis** — static triage for researchers & forensic analysts:
  file hashes (MD5/SHA-1/SHA-256), dangerous-permission analysis (accessibility,
  overlay, SMS, device-admin, boot-persist, …, each with why it matters),
  suspicious API/behavior signatures (accessibility abuse, screen overlays,
  dynamic code loading, SMS/OTP interception, emulator/root evasion, and more),
  network IOCs (URLs / domains / IPs, de-noised of Java-package false hits),
  known-packer detection, and correlated-indicator combos (e.g. accessibility +
  overlay = classic banker pattern) — rolled into a triage-priority score.
  Heuristic and read-only: nothing is executed. Also a **decompiled-Java view**:
  pick an app class → view its source decompiled by **jadx** (optional tool;
  falls back to a clear notice, with Jimple IR always available in Forensic
  mode). See [docs/FORENSIC.md](docs/FORENSIC.md).
- **🧪 Suspicious App Code** — investigate a suspicious APK/XAPK with
  **[DroidLysis](https://github.com/cryptax/droidlysis)**: it unpacks the app,
  disassembles every DEX to Smali, and pattern-matches the code, the raw
  strings and the native ARM libraries against its rule sets. Hits are grouped
  by concern (evasion & anti-analysis, dynamic code & packing, device & user
  surveillance, privilege & persistence, network & exfiltration, device
  fingerprinting), and each one is shown with the rule that fired **and why it
  matters** — the descriptions are read back out of DroidLysis' own config, so
  a hit explains itself instead of being a bare rule name. Also surfaces URLs,
  phone numbers and Base64 blobs found in the app, plus the third-party
  ad/analytics SDKs it recognises. Optional tool; when it (or its unpacking
  tools) are missing, the tab says so rather than reporting a hollow result as
  a clean one. Read-only; nothing is executed.
- **💉 Hacking** — inject `Log.d("SootInjection", "Entering: <method sig>")` at
  the start of every targeted method via Soot (`LogInjector.java`), then
  zipalign + apksign the result. Optionally install the injected APK on a
  connected device/emulator and capture logcat live.

## Documentation

The README is the overview. Detailed, code-level docs live in [`docs/`](docs/):

| Doc | Covers |
|---|---|
| [docs/JIMPLE.md](docs/JIMPLE.md) | **Jimple for beginners** — what Soot's IR is, how to read every statement/invoke/label form, exceptions & traps, a worked method, and how it maps to the CFG, the call graph and the injected log line |
| [docs/SETUP.md](docs/SETUP.md) | **Setup from scratch** (Windows/macOS/Linux): JDK + Node, the Android SDK, where the platform JARs live for Soot, installing `apksigner`/`zipalign`, and preparing a device |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the pieces fit; request flow; sync vs async+SSE; directory layout; design choices |
| [docs/FORENSIC.md](docs/FORENSIC.md) | The static scan (`inspector.js`), the Jimple/CFG explorer (`jimple.js` + `JimpleDumper.java`), the APK file browser (`files.js`), the malware triage (`malware.js`), the jadx decompiled-Java view (`decompile.js`), and the DroidLysis suspicious-code tab (`droidlysis.js`) |
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
| Package metadata + file browser decoding | `aapt2` (build-tools) — optional |
| Decompiled-Java view (Malware mode) | `jadx` on `PATH` or in `JADX_HOME` — optional |

Tool availability is shown as chips in the UI; missing tools degrade
gracefully (e.g. forensic scan falls back to a pure-JS ZIP reader when `unzip`
is absent, so it works on Windows too).

Cross-platform: Windows, macOS, Linux (paths, classpath separators, and
build-tool extensions are handled per-OS in `lib/tools.js`).

**New machine?** [docs/SETUP.md](docs/SETUP.md) is a from-scratch walkthrough
for all three OSes — installing the SDK, where the platform JARs live for Soot,
getting `apksigner`/`zipalign`, and preparing a device.

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
