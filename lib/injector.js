/**
 * lib/injector.js  — HACKING MODE (inject)
 *
 * Pipeline: compile LogInjector.java (if needed) → run Soot LogInjector on the
 * APK → zipalign + apksigner the output. Every step streams its output through
 * the `log` callback so the web UI can show progress live.
 *
 * Adapted from MADPro command-line-tool/commands/inject.js.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawnSync } = require("child_process");
const { run } = require("./runner");
const {
  IS_WIN, CP_SEP,
  findBin, findBuildTool, findAndroidPlatforms, jarClasspath,
  JAR_LIBS_DIR, JAVA_SRC_DIR, INJECTOR_CLASS,
} = require("./tools");
const bundle = require("./bundle");

// log(line, stream) — stream is "out" | "err" | "sys"
function mkLog(log) { return (line, stream = "sys") => log && log(line, stream); }

async function ensureCompiled(log, force = false) {
  const emit = mkLog(log);
  const src = path.join(JAVA_SRC_DIR, "LogInjector.java");

  const splicerSrc   = path.join(JAVA_SRC_DIR, "DexSplicer.java");
  const splicerClass = path.join(JAVA_SRC_DIR, "DexSplicer.class");

  if (!fs.existsSync(src)) { emit(`ERROR: LogInjector.java not found at ${src}`, "err"); return false; }
  if (!jarClasspath())     { emit(`ERROR: no jars in ${JAR_LIBS_DIR}`, "err"); return false; }

  const upToDate = f => {
    try { return fs.existsSync(f.cls) && fs.statSync(f.src).mtimeMs <= fs.statSync(f.cls).mtimeMs; }
    catch { return false; }
  };
  const targets = [{ src, cls: INJECTOR_CLASS }, { src: splicerSrc, cls: splicerClass }]
    .filter(t => fs.existsSync(t.src));

  if (!force && targets.every(upToDate)) {
    emit("[INFO] LogInjector + DexSplicer already compiled and up-to-date.");
    return true;
  }

  const javac = findBin("javac") || "javac";
  emit("--- Compiling LogInjector.java + DexSplicer.java ---");
  const ok = await run(javac, ["-cp", jarClasspath(), "-d", JAVA_SRC_DIR, ...targets.map(t => t.src)], { onLine: log });
  emit(ok ? "[OK] Compiled." : "[ERROR] Compilation failed — is a JDK installed?", ok ? "sys" : "err");
  return ok;
}

// Splice injected classes back onto the original APK's dex so untouched classes
// keep their exact original bytecode (avoids Soot DEX re-encode corruption).
// Returns the spliced APK path, or null on failure.
async function spliceDex({ originalApk, injectedApk, classList, outApk, log }) {
  const emit = mkLog(log);
  if (!fs.existsSync(classList)) {
    emit(`[WARN] no injected-classes list — skipping dex splice (output may VerifyError on modern apps).`, "err");
    return null;
  }
  const cp = [JAVA_SRC_DIR, jarClasspath()].join(CP_SEP);
  const java = findBin("java") || "java";
  emit(`[INFO] Splicing injected classes onto original dex…`);
  const ok = await run(java, ["-Xmx4g", "-cp", cp, "DexSplicer", originalApk, injectedApk, outApk, classList],
    { onLine: log, timeoutMs: 5 * 60 * 1000, stuckMs: 2 * 60 * 1000 });
  if (!ok || !fs.existsSync(outApk)) { emit(`[WARN] dex splice failed — falling back to Soot output.`, "err"); return null; }
  return outApk;
}

// Sign every .apk under outputDir (in place) via zipalign + apksigner.
async function signApks(outputDir, log, opts = {}) {
  const emit = mkLog(log);
  const zipalign  = findBuildTool("zipalign");
  const apksigner = findBuildTool("apksigner");
  if (!zipalign || !apksigner) {
    emit("[WARN] zipalign/apksigner not found — injected APK left UNSIGNED (won't install as-is).", "err");
    return;
  }

  const keystore = path.join(os.homedir(), ".android", "debug.keystore");
  if (!fs.existsSync(keystore)) {
    emit("[INFO] Generating debug keystore…");
    fs.mkdirSync(path.dirname(keystore), { recursive: true });
    const keytool = findBin("keytool") || "keytool";
    spawnSync(keytool, [
      "-genkeypair", "-v", "-keystore", keystore,
      "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
      "-validity", "10000", "-storepass", "android", "-keypass", "android",
      "-dname", "CN=Android Debug,O=Android,C=US",
    ], { encoding: "utf8" });
  }

  const apks = (opts.onlyApks || fs.readdirSync(outputDir))
    .filter(f => f.toLowerCase().endsWith(".apk"));
  for (const name of apks) {
    if (name.endsWith("-aligned.apk")) continue;
    const apk = path.join(outputDir, name);
    const aligned = apk.replace(/\.apk$/i, "-aligned.apk");
    emit(`  Signing: ${name}`);
    const zOk = await run(zipalign, ["-f", "-v", "4", apk, aligned], { onLine: log });
    if (!zOk) { emit(`  [WARN] zipalign failed for ${name}`, "err"); continue; }
    const sOk = await run(apksigner, [
      "sign", "--ks", keystore, "--ks-pass", "pass:android",
      "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
      "--out", apk, aligned,
    ], { onLine: log });
    try { fs.unlinkSync(aligned); } catch {}
    emit(sOk ? `  [OK] Signed: ${name}` : `  [WARN] apksigner failed for ${name}`, sOk ? "sys" : "err");
  }
}

/**
 * inject({ apkPath, outputDir, injectAll, patterns, log }) -> { ok, outputDir }
 *
 * injectAll  — true: instrument all methods (-inject-all).
 * patterns   — array of class-filter globs (e.g. ["com.google.android.gms.ads.*"]).
 *              Ignored when injectAll is true.
 *
 * Note: LogInjector's built-in exclude list blocks framework/GMS/ads packages
 * even under --inject-all to avoid ART VerifyErrors. To hit AdMob classes you
 * must pass an explicit pattern (non-inject-all mode) — the UI warns about this.
 */
// Run Soot LogInjector on one APK, writing the injected APK into sootOutDir.
// Returns { ok, error }. Does not sign.
async function runSoot({ apkPath, sootOutDir, injectAll, patterns, log }) {
  const emit = mkLog(log);
  fs.mkdirSync(sootOutDir, { recursive: true });
  const cp = [JAVA_SRC_DIR, jarClasspath()].join(CP_SEP);

  // Heap: inject-all loads every method body of the whole APK, so large apps
  // (100 MB+) blow past a small heap and Soot dies with OutOfMemoryError,
  // leaving no output. Default to 8g (override with SOOTSLEUTH_HEAP, e.g. "12g").
  const heap = process.env.SOOTSLEUTH_HEAP || (injectAll ? "8g" : "4g");

  const javaArgs = [
    `-Xmx${heap}`, "-Xms512m", "-XX:+UseG1GC",
    "-XX:MaxGCPauseMillis=200", "-XX:SoftRefLRUPolicyMSPerMB=0",
    "-XX:StringTableSize=1000003",
    "-XX:+ExitOnOutOfMemoryError",
    "-cp", cp, "LogInjector",
  ];
  if (injectAll) javaArgs.push("--inject-all");
  javaArgs.push(platformsPathCache, apkPath, sootOutDir);
  const filterCsv = (patterns || []).join(",");
  if (!injectAll && filterCsv) javaArgs.push(filterCsv);

  const java = findBin("java") || "java";
  emit(`--- Injecting: ${path.basename(apkPath)} ---`);
  emit(`    Mode: ${injectAll ? "inject-all" : (filterCsv || "(no filter → all app classes)")}`);
  emit(`    Heap: -Xmx${heap}`);

  let sawOOM = false;
  const oomWatch = (line, stream) => {
    if (/OutOfMemoryError|ExitOnOutOfMemoryError|GC overhead limit/.test(line)) sawOOM = true;
    log && log(line, stream);
  };

  const ok = await run(java, javaArgs, {
    onLine: oomWatch, filterSoot: true,
    timeoutMs: 15 * 60 * 1000, stuckMs: 3 * 60 * 1000,
  });

  if (!ok) {
    if (sawOOM) {
      emit(`[FAILED] Soot ran out of memory (heap -Xmx${heap} exhausted).`, "err");
      emit(`         Fix: use a narrower Custom class filter (e.g. com.google.android.gms.ads.*),`, "err");
      emit(`         or raise the heap by starting the server with SOOTSLEUTH_HEAP=12g.`, "err");
      return { ok: false, error: "OutOfMemoryError" };
    }
    emit(`[FAILED] injection`, "err");
    return { ok: false, error: "soot-failed" };
  }

  const produced = fs.readdirSync(sootOutDir).filter(f => f.toLowerCase().endsWith(".apk"));
  if (!produced.length) {
    emit(`[FAILED] Soot produced no output APK.` + (sawOOM ? " (out of memory)" : ""), "err");
    return { ok: false, error: sawOOM ? "OutOfMemoryError" : "no-output" };
  }
  return { ok: true };
}

let platformsPathCache = null;

async function inject({ apkPath, outputDir, injectAll = true, patterns = [], log }) {
  const emit = mkLog(log);

  if (!await ensureCompiled(log)) return { ok: false, outputDir };

  const platforms = findAndroidPlatforms();
  if (!platforms) {
    emit("ERROR: Android platforms not found. Set ANDROID_HOME or install the Android SDK.", "err");
    return { ok: false, outputDir };
  }
  platformsPathCache = platforms;
  emit(`[INFO] Android platforms: ${platforms}`);
  fs.mkdirSync(outputDir, { recursive: true });

  return bundle.isBundle(apkPath)
    ? injectBundle({ apkPath, outputDir, injectAll, patterns, log })
    : injectSingle({ apkPath, outputDir, injectAll, patterns, log });
}

// Plain APK: inject → sign in place.
async function injectSingle({ apkPath, outputDir, injectAll, patterns, log }) {
  const emit = mkLog(log);
  const r = await runSoot({ apkPath, sootOutDir: outputDir, injectAll, patterns, log });
  if (!r.ok) return { ok: false, outputDir, error: r.error };

  // Splice: replace Soot's re-encoded output with a version where only the
  // injected classes come from Soot and everything else is the original dex.
  const produced = fs.readdirSync(outputDir).filter(f => f.toLowerCase().endsWith(".apk"));
  const injectedApk = path.join(outputDir, produced.find(f => f === path.basename(apkPath)) || produced[0]);
  const spliced = await spliceDex({
    originalApk: apkPath, injectedApk,
    classList: path.join(outputDir, "injected-classes.txt"),
    outApk: injectedApk + ".spliced", log,
  });
  if (spliced) { fs.renameSync(spliced, injectedApk); emit(`[OK] Dex-spliced (only injected classes changed).`); }

  emit(`[OK] Injection done → ${outputDir}`);
  await signApks(outputDir, log);
  const apks = fs.readdirSync(outputDir).filter(f => f.toLowerCase().endsWith(".apk"));
  return { ok: true, outputDir, apks };
}

/**
 * XAPK/.apks: unpack → inject the base APK → re-sign the injected base AND every
 * split with one debug key (Android requires a uniform signer across the split
 * set) → repack into a new .xapk containing the injected base + all splits +
 * manifest.json + icon, so the result installs as a complete bundle.
 */
async function injectBundle({ apkPath, outputDir, injectAll, patterns, log }) {
  const emit = mkLog(log);
  const ext = path.extname(apkPath).toLowerCase();
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "sootsleuth-inject-"));
  const unpackDir = path.join(workDir, "unpacked");

  try {
    emit(`[INFO] Bundle detected (${ext}) — unpacking…`);
    bundle.unpack(apkPath, unpackDir);
    const manifest = bundle.readManifest(unpackDir);
    const baseApk = bundle.findBaseApk(unpackDir, manifest);
    if (!baseApk) { emit("[FAILED] no base APK inside bundle.", "err"); return { ok: false, outputDir, error: "no-base" }; }

    const allApks = fs.readdirSync(unpackDir).filter(f => /\.apk$/i.test(f));
    const splits = allApks.filter(f => f !== baseApk);
    emit(`[INFO] Base: ${baseApk} · ${splits.length} split(s): ${splits.join(", ") || "(none)"}`);

    // 1. Inject the base APK into a scratch dir.
    const sootOut = path.join(workDir, "soot-out");
    const r = await runSoot({ apkPath: path.join(unpackDir, baseApk), sootOutDir: sootOut, injectAll, patterns, log });
    if (!r.ok) return { ok: false, outputDir, error: r.error };

    // Soot names its output after the input; find the produced APK.
    const injected = fs.readdirSync(sootOut).filter(f => f.toLowerCase().endsWith(".apk"));
    const injectedBase = injected.find(f => f === baseApk) || injected[0];
    const injectedBasePath = path.join(sootOut, injectedBase);

    // Splice injected classes back onto the ORIGINAL base dex, then place the
    // spliced base over the unpacked base (keeps the original base filename).
    const origBasePath = path.join(unpackDir, baseApk);
    const spliced = await spliceDex({
      originalApk: origBasePath, injectedApk: injectedBasePath,
      classList: path.join(sootOut, "injected-classes.txt"),
      outApk: path.join(sootOut, "spliced-base.apk"), log,
    });
    fs.copyFileSync(spliced || injectedBasePath, origBasePath);
    emit(spliced ? `[OK] Injected + dex-spliced base APK: ${baseApk}` : `[OK] Injected base APK: ${baseApk}`);

    // 2. Re-sign the injected base + every split with the same debug key.
    //    (zipalign+apksigner over each .apk in unpackDir.)
    emit(`[INFO] Re-signing base + ${splits.length} split(s) with one key…`);
    await signApks(unpackDir, log, { onlyApks: allApks });

    // 3. Repack into a new bundle with injected base + all splits + extras.
    const bundleName = path.basename(apkPath).replace(new RegExp(`\\${ext}$`, "i"), `-injected${ext}`);
    const outBundle = path.join(outputDir, bundleName);
    const packFiles = fs.readdirSync(unpackDir)
      .filter(f => !/-aligned\.apk$/i.test(f))          // drop signing scratch
      .filter(f => !/\.idsig$/i.test(f))                // drop apksigner v4 side-files
      .map(f => path.join(unpackDir, f));
    emit(`[INFO] Repacking ${packFiles.length} file(s) → ${bundleName}`);
    bundle.repack(outBundle, packFiles);
    emit(`[OK] Wrote injected bundle: ${outBundle}`);

    return { ok: true, outputDir, apks: [bundleName], bundle: true };
  } catch (e) {
    emit(`[FAILED] bundle injection: ${e.message}`, "err");
    return { ok: false, outputDir, error: e.message };
  } finally {
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}
  }
}

module.exports = { inject, ensureCompiled, signApks };
