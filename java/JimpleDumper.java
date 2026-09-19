import soot.*;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.jimple.IfStmt;
import soot.jimple.GotoStmt;
import soot.jimple.SwitchStmt;
import soot.jimple.ThrowStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;

import java.util.*;

/**
 * JimpleDumper — FORENSIC helper: expose Soot's Jimple IR and control-flow graph
 * of the application's own classes for read-only inspection in the web UI.
 *
 * All output is machine-consumable (plain text or JSON) so server.js can relay
 * it to the browser. No bytecode is modified.
 *
 * Modes:
 *   --classes <android-platforms> <apk>
 *       → one app class name per line (com.foo.Bar).
 *
 *   --methods <android-platforms> <apk> <class>
 *       → one method per line: "<subsignature>\t<jimple-name>" where subsignature
 *         is Soot's method subsignature (unique within a class).
 *
 *   --jimple  <android-platforms> <apk> <class> [subsignature]
 *       → Jimple source text. Whole class if subsignature omitted, else one method.
 *
 *   --cfg     <android-platforms> <apk> <class> <subsignature>
 *       → JSON { "method": "...", "nodes":[{id,text}], "edges":[{from,to,kind}] }
 *         built from a BriefUnitGraph. Edge kind ∈ {branch,fall,switch,goto,exc}.
 */
public class JimpleDumper {

    public static void main(String[] args) {
        if (args.length < 3) { usage(); return; }
        String mode = args[0];
        String platforms = args[1];
        String apk = args[2];

        setupSoot(platforms, apk);

        switch (mode) {
            case "--classes": listClasses(); break;
            case "--methods": listMethods(arg(args, 3)); break;
            case "--jimple":  dumpJimple(arg(args, 3), arg(args, 4)); break;
            case "--cfg":     dumpCfg(arg(args, 3), arg(args, 4)); break;
            default: usage();
        }
    }

    private static String arg(String[] a, int i) { return i < a.length ? a[i] : null; }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  java JimpleDumper --classes <platforms> <apk>");
        System.err.println("  java JimpleDumper --methods <platforms> <apk> <class>");
        System.err.println("  java JimpleDumper --jimple  <platforms> <apk> <class> [subsig]");
        System.err.println("  java JimpleDumper --cfg     <platforms> <apk> <class> <subsig>");
        System.exit(1);
    }

    private static void setupSoot(String androidPlatforms, String apk) {
        G.reset();
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_validate(false);
        Options.v().set_search_dex_in_archives(true);
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_none); // read-only, no write
        Options.v().set_android_jars(androidPlatforms);
        Options.v().set_full_resolver(false);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_num_threads(1);

        List<String> dirs = new ArrayList<>();
        dirs.add(apk);
        Options.v().set_process_dir(dirs);

        Scene.v().loadNecessaryClasses();
    }

    private static void listClasses() {
        List<String> names = new ArrayList<>();
        for (SootClass sc : Scene.v().getApplicationClasses()) names.add(sc.getName());
        Collections.sort(names);
        for (String n : names) System.out.println(n);
    }

    private static SootClass resolveClass(String className) {
        if (className == null) { System.err.println("ERROR: class name required"); System.exit(2); }
        if (!Scene.v().containsClass(className)) {
            System.err.println("ERROR: class not found: " + className);
            System.exit(2);
        }
        SootClass sc = Scene.v().getSootClass(className);
        sc.setApplicationClass();
        return sc;
    }

    private static void listMethods(String className) {
        SootClass sc = resolveClass(className);
        for (SootMethod m : new ArrayList<>(sc.getMethods())) {
            System.out.println(m.getSubSignature() + "\t" + m.getName());
        }
    }

    // Load a concrete method body, tolerating obfuscated/broken bodies.
    private static Body activeBody(SootMethod m) {
        if (m.isAbstract() || m.isNative() || m.isPhantom()) return null;
        try { return m.retrieveActiveBody(); }
        catch (Exception e) { return null; }
    }

    private static void dumpJimple(String className, String subsig) {
        SootClass sc = resolveClass(className);
        if (subsig != null) {
            SootMethod m = findMethod(sc, subsig);
            if (m == null) { System.err.println("ERROR: method not found: " + subsig); System.exit(2); }
            Body b = activeBody(m);
            if (b == null) { System.out.println("// no body (abstract/native/unresolvable): " + m.getSubSignature()); return; }
            System.out.println(b.toString());
        } else {
            System.out.println("// class " + sc.getName());
            for (SootMethod m : new ArrayList<>(sc.getMethods())) {
                System.out.println();
                System.out.println("// " + m.getSubSignature());
                Body b = activeBody(m);
                System.out.println(b == null ? "//   (no body)" : b.toString());
            }
        }
    }

    private static SootMethod findMethod(SootClass sc, String subsig) {
        for (SootMethod m : new ArrayList<>(sc.getMethods()))
            if (m.getSubSignature().equals(subsig)) return m;
        return null;
    }

    // Emit the method's CFG as JSON built from a BriefUnitGraph. Each Jimple unit
    // is a node; edges carry a kind so the UI can style branch vs fall-through vs
    // exception flow differently.
    private static void dumpCfg(String className, String subsig) {
        SootClass sc = resolveClass(className);
        SootMethod m = findMethod(sc, subsig);
        if (m == null) { System.err.println("ERROR: method not found: " + subsig); System.exit(2); }
        Body body = activeBody(m);
        if (body == null) {
            System.out.println("{\"method\":" + jstr(subsig) + ",\"nodes\":[],\"edges\":[],\"note\":\"no body\"}");
            return;
        }

        // ExceptionalUnitGraph includes exception-handler edges (try→catch), so
        // the CFG shows control flow into catch blocks — important for forensics.
        UnitGraph g = new ExceptionalUnitGraph(body);
        // Stable ids: index in the unit chain order.
        Map<Unit, Integer> id = new LinkedHashMap<>();
        int i = 0;
        for (Unit u : body.getUnits()) id.put(u, i++);

        StringBuilder nodes = new StringBuilder();
        for (Map.Entry<Unit, Integer> e : id.entrySet()) {
            Unit u = e.getKey();
            if (nodes.length() > 0) nodes.append(",");
            nodes.append("{\"id\":").append(e.getValue())
                 .append(",\"text\":").append(jstr(u.toString()))
                 .append(",\"kind\":").append(jstr(nodeKind(u)))
                 .append("}");
        }

        StringBuilder edges = new StringBuilder();
        for (Unit u : body.getUnits()) {
            int from = id.get(u);
            List<Unit> succs = g.getSuccsOf(u);
            for (Unit s : succs) {
                Integer to = id.get(s);
                if (to == null) continue;
                if (edges.length() > 0) edges.append(",");
                edges.append("{\"from\":").append(from)
                     .append(",\"to\":").append(to)
                     .append(",\"kind\":").append(jstr(edgeKind(u, s, id))).append("}");
            }
        }

        System.out.println("{\"method\":" + jstr(m.getSubSignature())
            + ",\"nodes\":[" + nodes + "],\"edges\":[" + edges + "]}");
    }

    private static String nodeKind(Unit u) {
        if (u instanceof IfStmt) return "branch";
        if (u instanceof SwitchStmt) return "switch";
        if (u instanceof GotoStmt) return "goto";
        if (u instanceof ThrowStmt) return "throw";
        if (u instanceof ReturnStmt || u instanceof ReturnVoidStmt) return "return";
        return "stmt";
    }

    // Classify an edge relative to its source unit so the UI can color it.
    private static String edgeKind(Unit from, Unit to, Map<Unit, Integer> id) {
        if (from instanceof IfStmt) {
            Unit target = ((IfStmt) from).getTarget();
            return target == to ? "branch" : "fall";
        }
        if (from instanceof GotoStmt) return "goto";
        if (from instanceof SwitchStmt) return "switch";
        // fall-through when the successor is the immediate next unit, else a jump.
        Integer f = id.get(from), t = id.get(to);
        if (f != null && t != null && t == f + 1) return "fall";
        return "exc";
    }

    // Minimal JSON string escaper.
    private static String jstr(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append("\"").toString();
    }
}
