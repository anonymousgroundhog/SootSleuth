import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.zip.*;

/**
 * DexSplicer — rebuild an APK's dex set so ONLY the classes Soot actually
 * injected are taken from Soot's (re-encoded) output; every other class is kept
 * byte-for-byte from the ORIGINAL apk.
 *
 * Why: Soot 4.7.1's DEX backend round-trips every class through Jimple and
 * re-encodes it, which corrupts certain synthetic classes (protobuf
 * GeneratedMessageLite$MethodToInvoke, kotlinx coroutines SharedFlowImpl, Room
 * DAO impls) — ART then rejects them with VerifyError. Splicing the injected
 * classes back onto the original dex avoids touching anything we didn't change.
 *
 * Usage:
 *   java DexSplicer <original-apk> <injected-apk> <output-apk> <injected-classes.txt>
 *
 * injected-classes.txt: one dotted class name per line (as written by
 * LogInjector). Names are normalized to dex type descriptors internally.
 */
public class DexSplicer {

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("Usage: java DexSplicer <original-apk> <injected-apk> <output-apk> <injected-classes.txt>");
            System.exit(1);
        }
        File originalApk = new File(args[0]);
        File injectedApk = new File(args[1]);
        File outputApk   = new File(args[2]);
        File classList   = new File(args[3]);

        // Injected class names → dex type descriptors: com.a.B → Lcom/a/B;
        Set<String> injectedTypes = new HashSet<>();
        for (String line : Files.readAllLines(classList.toPath())) {
            String c = line.trim();
            if (c.isEmpty()) continue;
            injectedTypes.add("L" + c.replace('.', '/') + ";");
        }
        System.out.println("[splice] injected classes: " + injectedTypes.size());

        // Use the ORIGINAL apk's own dex opcodes for reading and writing so the
        // encoding matches exactly — the default opcode set can mis-encode
        // interface dispatch for newer dex versions (IncompatibleClassChangeError).
        Opcodes opcodes;
        {
            MultiDexContainer<? extends DexFile> probe =
                DexFileFactory.loadDexContainer(originalApk, Opcodes.getDefault());
            String first = probe.getDexEntryNames().get(0);
            opcodes = probe.getEntry(first).getDexFile().getOpcodes();
            System.out.println("[splice] using original dex opcodes: " + opcodes.api);
        }

        // Load the injected classes from Soot's output (only the ones we want).
        Map<String, ClassDef> injectedDefs = new HashMap<>();
        MultiDexContainer<? extends DexFile> injContainer =
            DexFileFactory.loadDexContainer(injectedApk, opcodes);
        for (String entry : injContainer.getDexEntryNames()) {
            DexFile df = injContainer.getEntry(entry).getDexFile();
            for (ClassDef cd : df.getClasses()) {
                if (injectedTypes.contains(cd.getType())) injectedDefs.put(cd.getType(), cd);
            }
        }
        System.out.println("[splice] matched injected defs: " + injectedDefs.size());

        // KEY: only rebuild the original dex files that actually contain an
        // injected class. Every other dex is copied byte-for-byte from the
        // original apk, so classes we never touched keep their exact original
        // bytecode — this is what prevents dexlib2 re-encoding from breaking
        // unrelated classes (e.g. Compose interfaces → IncompatibleClassChangeError).
        // Injected classes stay in the same dex entry they came from, so there
        // are never duplicate class definitions across dex files.
        Path workDir = Files.createTempDirectory("dexsplice-");
        List<File> dexFiles = new ArrayList<>();
        MultiDexContainer<? extends DexFile> origContainer =
            DexFileFactory.loadDexContainer(originalApk, opcodes);

        int outIndex = 1;
        int rebuilt = 0, copied = 0, replaced = 0;
        // Preserve the original entry order (classes.dex, classes2.dex, …).
        List<String> entryNames = new ArrayList<>(origContainer.getDexEntryNames());
        Collections.sort(entryNames, DexSplicer::dexOrder);

        for (String entry : entryNames) {
            DexFile df = origContainer.getEntry(entry).getDexFile();
            boolean hasInjected = false;
            for (ClassDef cd : df.getClasses()) {
                if (injectedDefs.containsKey(cd.getType())) { hasInjected = true; break; }
            }

            File out = new File(workDir.toFile(), dexName(outIndex++));
            if (!hasInjected) {
                // Copy this dex verbatim from the original apk.
                extractZipEntry(originalApk, entry, out);
                copied++;
            } else {
                // Rebuild only this dex, swapping injected classes in place.
                DexPool pool = new DexPool(opcodes);
                for (ClassDef cd : df.getClasses()) {
                    ClassDef inj = injectedDefs.get(cd.getType());
                    if (inj != null) { pool.internClass(inj); replaced++; }
                    else pool.internClass(cd);
                }
                pool.writeTo(new FileDataStore(out));
                rebuilt++;
            }
            dexFiles.add(out);
        }
        System.out.println("[splice] dex files: " + dexFiles.size()
            + "  rebuilt: " + rebuilt + "  copied-verbatim: " + copied
            + "  classes replaced: " + replaced);

        // Repackage: copy the original apk, replacing classes*.dex entries with
        // our dex set and keeping everything else (resources, libs).
        rebuildApk(originalApk, outputApk, dexFiles);
        System.out.println("[splice] wrote spliced APK: " + outputApk.getAbsolutePath());
    }

    private static String dexName(int i) { return i == 1 ? "classes.dex" : "classes" + i + ".dex"; }

    // Order dex entry names as classes.dex, classes2.dex, classes3.dex, …
    private static int dexOrder(String a, String b) {
        return Integer.compare(dexNum(a), dexNum(b));
    }
    private static int dexNum(String name) {
        String base = name.substring(name.lastIndexOf('/') + 1);
        if (base.equals("classes.dex")) return 1;
        try { return Integer.parseInt(base.replaceAll("[^0-9]", "")); } catch (Exception e) { return 999; }
    }

    // Extract one entry from a zip/apk to a file (used to copy dex verbatim).
    private static void extractZipEntry(File apk, String entryName, File out) throws Exception {
        try (ZipFile zf = new ZipFile(apk)) {
            ZipEntry e = zf.getEntry(entryName);
            if (e == null) throw new java.io.IOException("entry not found: " + entryName);
            try (java.io.InputStream in = zf.getInputStream(e);
                 java.io.OutputStream os = Files.newOutputStream(out.toPath())) {
                byte[] buf = new byte[1 << 16]; int n;
                while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
            }
        }
    }

    private static void rebuildApk(File originalApk, File outputApk, List<File> dexFiles) throws Exception {
        Set<String> dexEntryNames = new HashSet<>();
        for (int i = 0; i < dexFiles.size(); i++) dexEntryNames.add(dexName(i + 1));

        try (ZipFile zin = new ZipFile(originalApk);
             ZipOutputStream zout = new ZipOutputStream(Files.newOutputStream(outputApk.toPath()))) {

            // Copy every original entry except the old dex files and existing
            // signature blocks (the apk will be re-signed downstream).
            Enumeration<? extends ZipEntry> entries = zin.entries();
            byte[] buf = new byte[1 << 16];
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (name.matches("classes\\d*\\.dex")) continue;
                if (name.startsWith("META-INF/") &&
                    (name.endsWith(".RSA") || name.endsWith(".SF") || name.endsWith(".MF"))) continue;

                ZipEntry ne = new ZipEntry(name);
                // Preserve STORE for already-compressed entries to avoid double
                // compression / alignment issues; DEFLATE the rest.
                if (e.getMethod() == ZipEntry.STORED) {
                    ne.setMethod(ZipEntry.STORED);
                    ne.setSize(e.getSize());
                    ne.setCompressedSize(e.getCompressedSize());
                    ne.setCrc(e.getCrc());
                } else {
                    ne.setMethod(ZipEntry.DEFLATED);
                }
                zout.putNextEntry(ne);
                try (java.io.InputStream in = zin.getInputStream(e)) {
                    int n; while ((n = in.read(buf)) > 0) zout.write(buf, 0, n);
                }
                zout.closeEntry();
            }

            // Add the merged dex files.
            for (int i = 0; i < dexFiles.size(); i++) {
                byte[] data = Files.readAllBytes(dexFiles.get(i).toPath());
                ZipEntry ne = new ZipEntry(dexName(i + 1));
                ne.setMethod(ZipEntry.DEFLATED);
                zout.putNextEntry(ne);
                zout.write(data);
                zout.closeEntry();
            }
        }
    }
}
