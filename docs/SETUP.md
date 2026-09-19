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
| `adb devices` empty | See the device-setup notes above (authorize the prompt; Linux udev; Windows USB driver). |
| Forensic permissions look empty | Install **aapt2** (Build-Tools). A binary `AndroidManifest.xml` yields nothing without it. |
