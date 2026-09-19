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
    platforms:         !!platforms,
    platformsPath:     platforms,
    injectorCompiled:  fs.existsSync(INJECTOR_CLASS),
    jarLibsExist:      !!jarClasspath(),
  };
}

module.exports = {
  IS_WIN, EXE, CP_SEP,
  which, findBin, findAdb, findBuildTool, findAndroidPlatforms,
  jarClasspath, checkTools,
  PROJECT_ROOT, JAR_LIBS_DIR, JAVA_SRC_DIR, INJECTOR_CLASS, UPLOADS_DIR, OUTPUT_DIR,
};
