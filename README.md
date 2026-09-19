# SootSleuth

Web tool for Android APK **forensics** and **Soot-powered log injection**.
Drag an APK into the browser and either investigate it or instrument it.

## Modes

- **🕵️ Forensic** — static inspection: ad-SDK detection (AdMob, AppLovin,
  Unity, IronSource, Meta, and more), Play Store / billing traces, package
  metadata, DEX count. Read-only.
- **💉 Hacking** — inject `Log.d("SootInjection", "Entering: <method sig>")` at
  the start of every targeted method via Soot (`LogInjector.java`), then
  zipalign + apksign the result. Optionally install the injected APK on a
  connected device/emulator and capture logcat live.

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

`.xapk` and `.apks` files are ZIP bundles containing a base APK plus
`config.*` split APKs and a `manifest.json`. SootSleuth handles them in both
modes:

- **Forensic** — unpacks to the inner base APK and inspects that; permissions
  come from `aapt2` (falling back to the XAPK `manifest.json`).
- **Hacking** — unpacks the bundle, injects the base APK, **re-signs the base
  and every split with one debug key** (Android requires a uniform signer
  across a split set), then repacks a new `<name>-injected.xapk` containing the
  injected base + all splits + `manifest.json` + icon. The whole bundle is what
  you download, so it installs as a complete app.

## Dex splicing (avoids VerifyError on modern apps)

Soot 4.7.1's DEX backend round-trips **every** class through Jimple and
re-encodes it, which corrupts certain synthetic classes (protobuf
`GeneratedMessageLite`, kotlinx coroutines `SharedFlowImpl`, Room DAOs, some
Compose interfaces) — ART then rejects them at runtime with `VerifyError` /
`IncompatibleClassChangeError`, even though those classes were never targeted.

SootSleuth fixes this with a **dex splice** (`java/DexSplicer.java`, dexlib2):

1. `LogInjector` records the classes it actually injected into
   (`injected-classes.txt`).
2. After Soot runs, `DexSplicer` rebuilds **only the dex files that contain an
   injected class**; every other `classes*.dex` is copied **byte-for-byte** from
   the original APK. Injected classes stay in their original dex entry, so there
   are no duplicate definitions.
3. It reads/writes with the original APK's own dex opcode set, so encoding
   matches exactly.

Result: injected classes carry the log calls; everything else is bit-identical
to the original → no VerifyErrors. Verified on device with a modern
Compose/coroutines/datastore app (AI Enlarger): 0 VerifyError, 0 crashes,
injection logs firing.

## Layout

```
server.js          Express server, upload, SSE job streaming
lib/tools.js       Cross-platform tool/SDK detection
lib/inspector.js   Forensic static analysis (unzip+strings or pure-JS)
lib/injector.js    Compile LogInjector → Soot inject → zipalign/apksign
lib/instrument.js  adb install → launch → logcat capture → uninstall
lib/runner.js      Subprocess spawner streaming lines to a callback
public/            Drag-drop web UI (index.html, app.js, style.css)
java/              LogInjector.java (Soot BodyTransformer) + compiled .class
jar_libs/          Soot 4.7.1 + dependencies
```

## Notes

- Uploads land in `uploads/<jobId>/`; injected output in `output/<jobId>/`.
  Both are gitignored and can be deleted freely.
- The injected APK is signed with a debug keystore
  (`~/.android/debug.keystore`, auto-generated) so it installs on dev devices.
