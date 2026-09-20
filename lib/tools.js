/**
 * lib/tools.js
 * Cross-platform binary/tool detection shared across SootSleuth.
 * Adapted from MADPro command-line-tool/lib/tools.js.
 */

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

const IS_WIN = process.platform === "win32";
const EXE = IS_WIN ? ".exe" : "";
const BAT = IS_WIN ? ".bat" : "";

// which/where wrapper — works on win (where), mac/linux (which).
function which(name) {
  try {
    const cmd = IS_WIN ? `where ${name}` : `which ${name}`;
    const out = execSync(cmd, { encoding: "utf8" }).trim();
    return out.split(/\r?\n/)[0] || null;
  } catch {
    return null;
  }
}

// Look for a binary on PATH, then in common install locations for each OS.
function findBin(name) {
  const fromPath = which(name) || which(name + EXE);
  if (fromPath) return fromPath;

  const home = os.homedir();
  const candidates = IS_WIN
    ? [
        path.join(home, ".cargo", "bin", name + EXE),
        path.join(home, ".local", "bin", name + EXE),
        `C:\\Program Files\\${name}\\${name}${EXE}`,
      ]
    : [
        path.join(home, ".cargo", "bin", name),
        path.join(home, ".local", "bin", name),
        "/usr/local/bin/" + name,
        "/usr/bin/" + name,
        "/opt/homebrew/bin/" + name,
      ];
  for (const p of candidates) if (fs.existsSync(p)) return p;
  return null;
}

// jadx (Dex-to-Java decompiler) — optional. Checks PATH, JADX_HOME/bin, and the
// usual install spots. The launcher is `jadx` (a shell script / `jadx.bat`).
function findJadx() {
  const fromPath = which("jadx") || which("jadx" + (IS_WIN ? ".bat" : ""));
  if (fromPath) return fromPath;
  const home = os.homedir();
  const bin = IS_WIN ? "jadx.bat" : "jadx";
  const roots = [
    process.env.JADX_HOME,
    "/opt/jadx", "/usr/local/opt/jadx", "/opt/homebrew/opt/jadx/libexec",
    path.join(home, "jadx"), path.join(home, ".local", "jadx"),
    path.join(home, "Applications", "jadx"),
  ].filter(Boolean);
  const candidates = [
    which(bin),
    "/usr/local/bin/jadx", "/opt/homebrew/bin/jadx",
    ...roots.map(r => path.join(r, "bin", bin)),
  ].filter(Boolean);
  for (const p of candidates) if (p && fs.existsSync(p)) return p;
  return null;
}

// DroidLysis (Android property extractor) — optional. Installed via
// `pip3 install droidlysis`, so the launcher usually lands in a pip bin dir
// (~/.local/bin, a virtualenv, or the Windows Scripts dir).
function findDroidlysis() {
  const name = "droidlysis" + (IS_WIN ? ".exe" : "");
  const fromPath = which("droidlysis") || which(name);
  if (fromPath) return fromPath;

  const home = os.homedir();
  const candidates = IS_WIN
    ? [
        path.join(home, "AppData", "Local", "Programs", "Python", "Scripts", name),
        path.join(home, "AppData", "Roaming", "Python", "Scripts", name),
      ]
    : [
        path.join(home, ".local", "bin", "droidlysis"),
        "/usr/local/bin/droidlysis",
        "/usr/bin/droidlysis",
        "/opt/homebrew/bin/droidlysis",
      ];
  if (process.env.DROIDLYSIS_HOME) {
    candidates.unshift(path.join(process.env.DROIDLYSIS_HOME, "droidlysis3.py"));
    candidates.unshift(path.join(process.env.DROIDLYSIS_HOME, "bin", "droidlysis"));
  }
  for (const p of candidates) if (fs.existsSync(p)) return p;
  return null;
}

// DroidLysis' conf/ directory (smali.conf, wide.conf, arm.conf, kit.conf and
// general.conf). We need it for two reasons: to pass --config explicitly (the
// default is resolved relative to the *current* directory), and to read each
// rule's description= so hits can be explained rather than just named.
function findDroidlysisConfig() {
  const home = os.homedir();
  const xdg = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  const roots = [
    process.env.DROIDLYSIS_CONF,
    process.env.DROIDLYSIS_HOME && path.join(process.env.DROIDLYSIS_HOME, "conf"),
    path.join(xdg, "droidlysis"),
    "/etc/droidlysis",
    path.join(home, "droidlysis", "conf"),
    path.join(home, ".droidlysis", "conf"),
  ].filter(Boolean);

  // Also look where pip put it. DroidLysis installs its modules flat into
  // site-packages (droidconfig.py, droidlysis3.py, …) with the rule files in a
  // sibling `conf/`, so we locate a known module and look next to it rather
  // than guessing the interpreter's layout.
  try {
    const out = execSync(
      `${IS_WIN ? "python" : "python3"} -c "import importlib.util,os;s=importlib.util.find_spec('droidconfig');print(os.path.dirname(s.origin) if s and s.origin else '')"`,
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 8000 }).trim();
    if (out) { roots.push(path.join(out, "conf")); roots.push(out); }
  } catch {}
  for (const r of roots) {
    if (r && fs.existsSync(path.join(r, "general.conf"))) return r;
  }
  return null;
}

// Which unpacking tools DroidLysis' general.conf points at, and whether each
// one actually exists. DroidLysis ships default paths (~/softs/...) that are
// wrong on most machines; when they're missing it still runs and still writes a
// report, but silently skips Smali disassembly and the dex2jar/manifest steps.
// A report produced that way looks clean because almost nothing was inspected,
// so callers need to know before presenting it as a result.
function droidlysisBackends() {
  const confDir = findDroidlysisConfig();
  const out = { confDir, apktool: null, baksmali: null, dex2jar: null, missing: [] };
  if (!confDir) return out;
  let text;
  try { text = fs.readFileSync(path.join(confDir, "general.conf"), "utf8"); }
  catch { return out; }

  for (const key of ["apktool", "baksmali", "dex2jar"]) {
    const m = text.match(new RegExp(`^\\s*${key}\\s*=\\s*(.+)$`, "m"));
    if (!m) { out.missing.push(key); continue; }
    let p = m[1].trim();
    if (p.startsWith("~")) p = path.join(os.homedir(), p.slice(1));
    out[key] = { path: p, exists: fs.existsSync(p) };
    if (!out[key].exists) out.missing.push(key);
  }
  return out;
}

function sdkRoots() {
  const home = os.homedir();
  return [
    process.env.ANDROID_HOME,
    process.env.ANDROID_SDK_ROOT,
    IS_WIN
      ? path.join(home, "AppData", "Local", "Android", "Sdk")
      : path.join(home, "Android", "Sdk"),
    path.join(home, "android-sdk"),
    path.join(home, "Library", "Android", "sdk"), // macOS default
    "/opt/android-sdk",
  ].filter(Boolean);
}

function findAdb() {
  for (const root of sdkRoots()) {
    const p = path.join(root, "platform-tools", "adb" + EXE);
    if (fs.existsSync(p)) return p;
  }
  return which("adb");
}

// Android build-tools binaries (zipalign/apksigner/aapt2). Picks newest version.
function findBuildTool(name) {
  // apksigner is a .bat on Windows, plain script on unix; zipalign/aapt2 are .exe on win.
  const winName = name === "apksigner" ? name + BAT : name + EXE;
  const fileName = IS_WIN ? winName : name;
  for (const root of sdkRoots()) {
    const btDir = path.join(root, "build-tools");
    if (!fs.existsSync(btDir)) continue;
    const versions = fs.readdirSync(btDir).sort().reverse();
    for (const v of versions) {
      const p = path.join(btDir, v, fileName);
      if (fs.existsSync(p)) return p;
    }
  }
  return which(name);
}

function findAndroidPlatforms() {
  for (const root of sdkRoots()) {
    const p = path.join(root, "platforms");
    try {
      if (fs.existsSync(p) && fs.readdirSync(p).length > 0) return p;
    } catch {}
  }
  // MADPro ships bundled platforms — check as a fallback for convenience.
  const bundled = path.join(os.homedir(), "Documents", "Projects", "MADPro", "android", "platforms");
  if (fs.existsSync(bundled) && fs.readdirSync(bundled).length > 0) return bundled;
  return null;
}

const PROJECT_ROOT   = path.resolve(__dirname, "..");
const JAR_LIBS_DIR   = path.join(PROJECT_ROOT, "jar_libs");
const JAVA_SRC_DIR   = path.join(PROJECT_ROOT, "java");
const INJECTOR_CLASS = path.join(JAVA_SRC_DIR, "LogInjector.class");
const UPLOADS_DIR    = path.join(PROJECT_ROOT, "uploads");
const OUTPUT_DIR     = path.join(PROJECT_ROOT, "output");

// Classpath separator differs: ";" on Windows, ":" elsewhere.
const CP_SEP = IS_WIN ? ";" : ":";

function jarClasspath() {
  if (!fs.existsSync(JAR_LIBS_DIR)) return "";
  return fs.readdirSync(JAR_LIBS_DIR)
    .filter(f => f.endsWith(".jar"))
    .map(f => path.join(JAR_LIBS_DIR, f))
    .join(CP_SEP);
}

// Snapshot of tool availability — surfaced in the web UI so users see what
// works on their machine (java required; adb/build-tools optional).
function checkTools() {
  const platforms = findAndroidPlatforms();
  return {
    platform:          process.platform,
    java:              !!findBin("java"),
    javac:             !!findBin("javac"),
    adb:               !!findAdb(),
    aapt2:             !!findBuildTool("aapt2"),
    zipalign:          !!findBuildTool("zipalign"),
    apksigner:         !!findBuildTool("apksigner"),
    unzip:             !!findBin("unzip"),
    strings:           !!findBin("strings"),
    jadx:              !!findJadx(),
    droidlysis:        !!findDroidlysis(),
    droidlysisConf:    !!findDroidlysisConfig(),
    platforms:         !!platforms,
    platformsPath:     platforms,
    injectorCompiled:  fs.existsSync(INJECTOR_CLASS),
    jarLibsExist:      !!jarClasspath(),
  };
}

module.exports = {
  IS_WIN, EXE, CP_SEP,
  which, findBin, findAdb, findBuildTool, findAndroidPlatforms, findJadx,
  findDroidlysis, findDroidlysisConfig, droidlysisBackends,
  jarClasspath, checkTools,
  PROJECT_ROOT, JAR_LIBS_DIR, JAVA_SRC_DIR, INJECTOR_CLASS, UPLOADS_DIR, OUTPUT_DIR,
};
