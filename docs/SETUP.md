# Setup from scratch

This guide takes a clean machine to a working SootSleuth on **Windows**,
**macOS**, and **Linux**. It covers the two things people trip on most:

1. the **Android platform JARs** Soot needs (`platforms/android-NN/android.jar`),
2. the build-tools binaries **`apksigner`** and **`zipalign`** (and `aapt2`),
   which ship inside the Android SDK.

At the end there's a section on preparing an **Android device** for the on-device
instrument step.

> You don't need Android Studio's IDE to *use* SootSleuth — you need the SDK
> pieces it installs. The fastest path is to install Android Studio once (it
> pulls the SDK, platforms, build-tools, and platform-tools for you), then let
> SootSleuth auto-discover everything. A no-IDE, command-line-only path is given
> at the end.

---

## What SootSleuth actually needs

| Requirement | Why | How it's found |
|---|---|---|
| **JDK 17+** (`java`, `javac`) | Runs Soot; compiles the Java helpers | `PATH` |
| **Node.js 18+** | The web server | `PATH` |
| **Android platform JARs** (`platforms/`) | Soot resolves framework types against `android.jar` | `ANDROID_HOME/platforms`, SDK defaults, or a bundled fallback |
| **`aapt2`** | Package metadata + permissions (forensic) | newest `build-tools/<ver>/` |
| **`zipalign` + `apksigner`** | Sign the injected APK so it installs | newest `build-tools/<ver>/` |
| **`adb`** + a device | On-device instrument (optional) | `platform-tools/`, then `PATH` |
| **`jadx`** | Decompiled-Java view in Malware mode (optional) | `PATH`, `JADX_HOME/bin`, or common install dirs |
| **`droidlysis`** | Suspicious App Code tab (optional) | `PATH`, pip bin dirs, or `DROIDLYSIS_HOME` |
| `unzip` / `strings` | Faster forensic scan (optional) | `PATH` — pure-JS fallback otherwise |

The repo's `jar_libs/` already contains Soot 4.7.1 and its dependencies, so you
do **not** install Soot separately.

Discovery is handled by `lib/tools.js` — see
[INTERNALS.md → tools.js](INTERNALS.md#libtoolsjs--cross-platform-discovery).
It searches, in order: `ANDROID_HOME` / `ANDROID_SDK_ROOT`, then the OS-default
SDK location, then a few common paths.

### The default SDK location per OS

| OS | Default `ANDROID_HOME` |
|---|---|
| Windows | `%LOCALAPPDATA%\Android\Sdk` (e.g. `C:\Users\you\AppData\Local\Android\Sdk`) |
| macOS | `~/Library/Android/sdk` |
| Linux | `~/Android/Sdk` |

Inside that SDK you'll have:

```
<sdk>/
  platforms/
    android-34/android.jar     ← the platform JARs Soot needs
    android-35/android.jar
  build-tools/
    35.0.0/
      aapt2  apksigner  zipalign   (.exe / .bat on Windows)
  platform-tools/
    adb
  cmdline-tools/latest/bin/
    sdkmanager  avdmanager
```

**Soot is pointed at the `platforms/` directory itself** (not a single
`android.jar`); it selects the right API level per APK. SootSleuth passes this
directory automatically.

---

## Step 0 — JDK and Node (all platforms)

Install a **JDK 17 or newer** and **Node.js 18+**, then verify:

```bash
java -version      # 17+  (this project is developed on 21)
javac -version
node -v            # 18+
```

- **Windows:** [Temurin JDK](https://adoptium.net) MSI + [Node.js](https://nodejs.org) MSI,
  or `winget install EclipseAdoptium.Temurin.21.JDK OpenJS.NodeJS.LTS`.
- **macOS:** `brew install temurin node` (or `brew install openjdk@21 node`).
- **Linux (Debian/Ubuntu):** `sudo apt install openjdk-21-jdk nodejs npm`
  (or use your distro's packages / nvm for Node).

---

## Step 1 — Install the Android SDK

### Option A — Android Studio (recommended, all platforms)

1. Download and install **Android Studio** from
   <https://developer.android.com/studio>.
2. Launch it and complete the **Setup Wizard** — accept the default
   "Standard" install. This downloads the SDK, a platform, build-tools, and
   platform-tools into the default location above.
3. Open **Settings/Preferences → Languages & Frameworks → Android SDK**
   (or **More Actions → SDK Manager** on the welcome screen):
   - **SDK Platforms** tab: tick at least one recent platform (e.g. **Android
     14 / API 34**). This is what puts `platforms/android-34/android.jar` on disk
     — the file Soot needs.
   - **SDK Tools** tab: ensure **Android SDK Build-Tools** and **Android SDK
     Platform-Tools** are checked. Build-Tools contains `apksigner`, `zipalign`,
     and `aapt2`; Platform-Tools contains `adb`.
   - Click **Apply** to download.
4. Note the **Android SDK Location** shown at the top of that page — that's your
   `ANDROID_HOME`.

### Option B — Command-line only (no IDE)

Install just the `sdkmanager` and use it to fetch the pieces.

1. Download **"Command line tools only"** from
   <https://developer.android.com/studio#command-tools> and unzip it so the path
   ends in `cmdline-tools/latest/` inside your chosen SDK dir. For example on
   Linux/macOS:

   ```bash
   export ANDROID_HOME="$HOME/Android/Sdk"          # macOS: $HOME/Library/Android/sdk
   mkdir -p "$ANDROID_HOME/cmdline-tools"
   # unzip the download, then:
   mv cmdline-tools "$ANDROID_HOME/cmdline-tools/latest"
   ```

2. Install the platform, build-tools, and platform-tools:

   ```bash
   cd "$ANDROID_HOME/cmdline-tools/latest/bin"
   yes | ./sdkmanager --licenses
   ./sdkmanager "platform-tools" "platforms;android-34" "build-tools;35.0.0"
   ```

   On **Windows** run the same from `cmdline-tools\latest\bin\` using
   `sdkmanager.bat` in PowerShell or CMD.

---

## Step 2 — Set `ANDROID_HOME` (recommended)

SootSleuth can find a default-located SDK on its own, but setting `ANDROID_HOME`
makes discovery unambiguous (and lets you use a non-default location).

### Windows (PowerShell, persistent)

```powershell
setx ANDROID_HOME "$env:LOCALAPPDATA\Android\Sdk"
# also handy for running adb/sdkmanager directly:
setx PATH "$env:PATH;$env:ANDROID_HOME\platform-tools;$env:ANDROID_HOME\cmdline-tools\latest\bin"
```

Close and reopen the terminal so the change takes effect.

### macOS / Linux (add to `~/.zshrc` or `~/.bashrc`)

```bash
# macOS
export ANDROID_HOME="$HOME/Library/Android/sdk"
# Linux
export ANDROID_HOME="$HOME/Android/Sdk"

export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin"
```

Then `source ~/.zshrc` (or open a new terminal).

> **`apksigner` / `zipalign` on `PATH`?** Not required — SootSleuth locates them
> inside `build-tools/<newest version>/` automatically. You only need them on
> `PATH` if you want to run them by hand.

---

## Step 3 — Get SootSleuth running

```bash
git clone git@github.com:anonymousgroundhog/SootSleuth.git
cd SootSleuth
npm install
npm start          # http://localhost:4700   (override with PORT=xxxx)
```

Open <http://localhost:4700>. The **tool chips** at the top show what was found:

```
✓ java  ✓ javac  ✓ Android SDK  ✓ adb  ✓ zipalign  ✓ apksigner  ✓ jars  …
```

You can also check from the API:

```bash
curl -s http://localhost:4700/api/tools
```

The Java helpers (`LogInjector`, `DexSplicer`, `JimpleDumper`) are compiled
**on demand** on first use against `jar_libs/` — you don't compile them by hand
(see [INTERNALS.md → Building the Java helpers](INTERNALS.md#building-the-java-helpers)).

---

## Verifying each requirement

Run these to confirm the pieces are where SootSleuth expects.

**Platform JARs (what Soot needs):**

```bash
# macOS
ls "$HOME/Library/Android/sdk/platforms"/*/android.jar
# Linux
ls "$HOME/Android/Sdk/platforms"/*/android.jar
```
```powershell
# Windows
Get-ChildItem "$env:LOCALAPPDATA\Android\Sdk\platforms\*\android.jar"
```
At least one `android.jar` must exist. No platform installed → the SDK Manager's
**SDK Platforms** tab (Step 1) is where you add one.

**Build-tools binaries:**

```bash
ls "$ANDROID_HOME/build-tools"/*/apksigner "$ANDROID_HOME/build-tools"/*/zipalign
"$ANDROID_HOME/build-tools/"*/apksigner --version    # any version prints a number
```
```powershell
Get-ChildItem "$env:ANDROID_HOME\build-tools\*\apksigner.bat","$env:ANDROID_HOME\build-tools\*\zipalign.exe"
```

**adb:**

```bash
adb version
```

---

## Installing jadx (optional — for the decompiled-Java view)

The **☕ Decompiled Java** view in Malware-analysis mode uses [jadx](https://github.com/skylot/jadx)
to turn DEX back into readable Java. It's optional — without it that view shows a
notice and the Jimple IR view in Forensic mode still works. jadx only needs a JDK
(already required for SootSleuth), so no extra runtime is involved.

SootSleuth locates jadx (via `lib/tools.js`'s `findJadx`) in this order:
`PATH` → `JADX_HOME/bin` → common install dirs (`/opt/jadx`, `~/.local/jadx`,
Homebrew, …). The `jadx` chip in the UI turns green once it's found. Verify any
install with `jadx --version`.

> **Prefer the official release zip over Snap.** The Snap package is sandboxed
> and cannot read APKs outside your home directory, which breaks the decompile
> step. The zip is self-contained and has no such restriction.

### Linux

The reliable path is the release zip installed into a discovered directory:

```bash
# Download the latest release zip (check the releases page for the current version)
VER=1.5.0
curl -L -o /tmp/jadx.zip \
  "https://github.com/skylot/jadx/releases/download/v${VER}/jadx-${VER}.zip"

# Install into ~/.local/jadx (a path SootSleuth searches) and link the launcher
rm -rf ~/.local/jadx && mkdir -p ~/.local/jadx
unzip -q /tmp/jadx.zip -d ~/.local/jadx
chmod +x ~/.local/jadx/bin/jadx ~/.local/jadx/bin/jadx-gui
mkdir -p ~/.local/bin
ln -sf ~/.local/jadx/bin/jadx ~/.local/bin/jadx

jadx --version    # ensure ~/.local/bin is on your PATH
```

If `~/.local/bin` isn't on your `PATH`, add `export PATH="$HOME/.local/bin:$PATH"`
to `~/.bashrc` (or `~/.zshrc`) — or just set `JADX_HOME=$HOME/.local/jadx`.

### macOS

```bash
brew install jadx        # simplest — puts jadx on your PATH
jadx --version
```

Or use the release zip exactly as in the Linux steps above (paths are identical
under your home directory).

### Windows

1. Download `jadx-<version>.zip` from the
   [releases page](https://github.com/skylot/jadx/releases) and unzip it, e.g. to
   `C:\Tools\jadx`.
2. Point SootSleuth at it, either by:
   - adding `C:\Tools\jadx\bin` to your **PATH** (System Properties →
     Environment Variables → Path → New), **or**
   - setting `JADX_HOME=C:\Tools\jadx` as a user environment variable.
3. Open a **new** terminal and verify:

   ```powershell
   jadx.bat --version
   ```

The Windows launcher is `bin\jadx.bat`; `findJadx` looks for it under `PATH` and
`JADX_HOME\bin`.

> Restart `npm start` after installing jadx so the server re-checks tools and the
> chip flips to green.

## Installing DroidLysis (optional — for the Suspicious App Code tab)

The **🧪 Suspicious App Code** tab uses
[DroidLysis](https://github.com/cryptax/droidlysis) to unpack the app,
disassemble its DEX to Smali and pattern-match the code, raw strings and native
libraries against its own rule sets. Without it the tab shows an install notice;
the Malware analysis tab works regardless.

```bash
pip3 install droidlysis
droidlysis --help          # confirm the launcher is on your PATH
```

SootSleuth finds the launcher via `findDroidlysis()` (`PATH`, `~/.local/bin`,
the Windows `Scripts` dir, or `DROIDLYSIS_HOME`) and the `droidlysis` chip turns
green once it's found.

### Also install its unpacking tools — this part is easy to miss

DroidLysis shells out to **apktool**, **baksmali** and **dex2jar**, and reads
their paths from its `general.conf`. The shipped defaults point at
`~/softs/...`, which won't exist on a fresh install.

This matters more than a normal missing-dependency: **DroidLysis does not fail
when they're absent.** It exits cleanly and still writes a report — it just
silently skips Smali disassembly and manifest parsing, producing a result with
zero code hits that looks indistinguishable from a clean app. SootSleuth detects
this and shows a warning banner naming the skipped layers, but you want the real
analysis:

```bash
mkdir -p ~/softs

# apktool (the official standalone jar — distro packages ship library jars
# without a main manifest, which DroidLysis cannot run)
curl -L -o ~/softs/apktool.jar \
  https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar

# baksmali (the "fat" jar — the Maven artifact is not self-executable)
curl -L -o ~/softs/baksmali.jar \
  https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar

# verify both actually run
java -jar ~/softs/apktool.jar --version
java -jar ~/softs/baksmali.jar --version

# dex2jar (only needed for DroidLysis' DEX→JAR step)
curl -L -o /tmp/dex-tools.zip \
  https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip
unzip -q /tmp/dex-tools.zip -d ~/softs
chmod +x ~/softs/dex-tools-v2.4/*.sh
```

Then point DroidLysis' config at them. Copy the shipped config somewhere it
searches — `~/.config/droidlysis/` is the cleanest choice, and SootSleuth looks
there first:

```bash
mkdir -p ~/.config/droidlysis
cp "$(python3 -c "import importlib.util,os;print(os.path.dirname(importlib.util.find_spec('droidconfig').origin))")"/conf/*.conf \
   ~/.config/droidlysis/
```

Edit `~/.config/droidlysis/general.conf` so the `[tools]` paths resolve:

```ini
[tools]
apktool = ~/softs/apktool.jar
baksmali = ~/softs/baksmali.jar
dex2jar = ~/softs/dex-tools-v2.4/d2j-dex2jar.sh
keytool = /usr/bin/keytool
```

SootSleuth resolves the config itself (`findDroidlysisConfig()`), searching
`DROIDLYSIS_CONF` → `DROIDLYSIS_HOME/conf` → `~/.config/droidlysis` →
`/etc/droidlysis` → the installed package's own `conf/`, and passes it
explicitly with `--config` (DroidLysis would otherwise resolve it relative to
the current directory). The `droidlysisConf` field in `GET /api/tools` reports
whether it was found.

> Restart `npm start` after installing so the server re-checks tools.

## Preparing an Android device (optional — for on-device instrument)

The **Install & capture logcat** button installs the injected APK on a real
device or emulator and streams its logs. Set one up:

### A physical device

1. On the phone: **Settings → About phone → tap "Build number" 7 times** to
   unlock **Developer options**.
2. **Settings → System → Developer options → enable "USB debugging"**.
3. Connect via USB. On the phone, **Allow** the "Allow USB debugging?" prompt
   for this computer.
4. Confirm the host sees it:

   ```bash
   adb devices
   # List of devices attached
   # ZT4229DSNS     device        ← "device" (not "unauthorized") means ready
   ```

   - `unauthorized` → re-accept the prompt on the phone.
   - empty on **Linux** → you likely need udev rules
     (`sudo apt install android-sdk-platform-tools-common`) and to replug.
   - empty on **Windows** → install the device's USB driver (or the
     [Google USB Driver](https://developer.android.com/studio/run/win-usb) via
     SDK Manager → SDK Tools).

### An emulator (no hardware needed)

Create and boot an AVD with the SDK you already installed:

```bash
sdkmanager "system-images;android-34;google_apis;x86_64"
avdmanager create avd -n test34 -k "system-images;android-34;google_apis;x86_64"
emulator -avd test34            # from $ANDROID_HOME/emulator
```

Once it's booted, `adb devices` lists it and it appears in SootSleuth's device
dropdown.

### Notes

- The injected APK is signed with a **debug keystore**
  (`~/.android/debug.keystore`, auto-created), so it installs on dev devices but
  not over a Play-signed copy — SootSleuth uninstalls any existing copy first.
- No device? Injection and download still work fully; only the instrument step
  needs `adb` + a device.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Chip: `✕ Android SDK` | No `platforms/` with an `android.jar`. Install a platform (Step 1) and/or set `ANDROID_HOME` (Step 2). |
| Chip: `✕ zipalign` / `✕ apksigner` | Build-Tools not installed. SDK Manager → SDK Tools → Android SDK Build-Tools. |
| Inject works but the APK won't install | Unsigned output — build-tools missing when it ran, or a signature clash. Check the console log; ensure zipalign/apksigner chips are green, reinject. |
| `OutOfMemoryError` during inject-all on a large app | Raise the heap: start the server with `SOOTSLEUTH_HEAP=12g npm start`, or use a narrow **Custom class filter** instead of inject-all. |
| Chip: `✕ java` / `✕ javac` | JDK not on `PATH`. Install a JDK 17+ (Step 0). `javac` is required to compile the helpers. |
| Chip: `✕ injector` | The Soot helper `java/LogInjector.class` isn't built yet. It compiles automatically on your first inject; to build it up front run `javac -cp "$(node -pe 'require(\"./lib/tools\").jarClasspath()')" -d java/ java/LogInjector.java java/DexSplicer.java`. Needs `javac` + `jars` chips green. |
| Chip: `✕ jadx` (Decompiled Java greyed out) | jadx not found. Install it (see *Installing jadx* above), put it on `PATH` or set `JADX_HOME`, then restart `npm start`. Avoid the Snap build — its sandbox can't read APKs and the decompile will fail. |
| `adb devices` empty | See the device-setup notes above (authorize the prompt; Linux udev; Windows USB driver). |
| Forensic permissions look empty | Install **aapt2** (Build-Tools). A binary `AndroidManifest.xml` yields nothing without it. |
