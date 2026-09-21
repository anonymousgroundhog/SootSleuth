# Jimple for beginners

SootSleuth's forensic mode shows you an app's code as **Jimple**. If you have
never seen Jimple before, this page is the place to start: what it is, why it
exists, how to read every line of it, and how the things you see in the UI
(the CFG, the call graph, the injected log line) map back to it.

You do **not** need to know Soot, compilers, or Dalvik bytecode to read this.

**Contents**

- [What is Jimple?](#what-is-jimple)
- [Why not just read the Java?](#why-not-just-read-the-java)
- [The shape of a Jimple method](#the-shape-of-a-jimple-method)
- [Three-address code, and why locals look weird](#three-address-code-and-why-locals-look-weird)
- [Types in Jimple](#types-in-jimple)
- [Signatures and subsignatures](#signatures-and-subsignatures)
- [The statement types](#the-statement-types)
- [The four invoke kinds](#the-four-invoke-kinds)
- [Field access](#field-access)
- [Arrays](#arrays)
- [Control flow: labels, gotos, ifs, switches](#control-flow-labels-gotos-ifs-switches)
- [Exceptions: traps and `@caughtexception`](#exceptions-traps-and-caughtexception)
- [Reading a whole method, line by line](#reading-a-whole-method-line-by-line)
- [Jimple in the SootSleuth UI](#jimple-in-the-sootsleuth-ui)
- [Jimple gotchas](#jimple-gotchas)
- [Cheat sheet](#cheat-sheet)
- [Where to go next](#where-to-go-next)

---

## What is Jimple?

**Jimple is an intermediate representation (IR): a simplified, typed,
statement-based form of a program that a tool works on instead of the original
bytecode.** It is the main IR of [Soot](https://github.com/soot-oss/soot), the
Java/Android analysis framework SootSleuth is built on.

The pipeline looks like this:

```
Java source  ──javac──▶  JVM bytecode  ──d8/dx──▶  Dalvik bytecode (classes.dex)
                                                            │
                                                          Soot
                                                            ▼
                                                         Jimple
```

When you drop an APK into SootSleuth, there is no Java source in it — an APK
ships only compiled `classes*.dex`. Soot reads that DEX and **lifts** it to
Jimple. Every class, method, and statement you see in the Jimple tab was
reconstructed from bytecode.

The name is a pun: **J**ava + s**imple**.

Three properties define it:

1. **Typed** — every local variable has a declared type, like Java. Raw DEX
   registers do not; their type depends on what happened to them earlier.
2. **Three-address** — each statement does at most *one* operation.
   `a = b + c`, never `a = b + c * d`.
3. **Small** — Java has ~200 constructs and DEX has ~230 opcodes; Jimple has
   **15 statement types**. That is the whole language. You can learn all of it
   in the time it takes to read this page.

That small size is the point. An analysis (or a human) that handles 15 cases
handles all of Android.

## Why not just read the Java?

You usually *can't*, and when you can, you can't trust it.

- An APK contains no source. Getting Java back means **decompiling**, which is
  a guess — a decompiler rebuilds `for` loops, ternaries, and lambdas from
  bytecode that no longer contains them.
- Decompilers **fail** on obfuscated, packed, or unusual code: you get
  `// Couldn't decompile method`, or worse, plausible-looking code that is
  subtly wrong.
- Jimple is a **mechanical, lossless-in-behaviour** translation of what is
  actually in the DEX. If the app does it, the Jimple shows it. There is no
  "this method wouldn't decompile" case — at worst a method is `abstract` or
  `native` and genuinely has no body.

The trade: Jimple is more verbose and less pretty than Java. For forensics
that is the right trade — you want *what the app really does*, not a readable
approximation.

SootSleuth gives you both. **Malware mode** has a jadx decompiled-Java view for
readability; **Forensic mode** has Jimple for ground truth. When they disagree,
Jimple is closer to the truth.

### Jimple vs. smali

Smali is the other thing people read APKs as. Smali is a *textual spelling of
DEX bytecode* — it is register-based, untyped, and stack-shaped:

```smali
# smali
const-string v0, "SootInjection"
const-string v1, "Entering: onCreate"
invoke-static {v0, v1}, Landroid/util/Log;->d(...)I
move-result v2
```

Jimple is the same code as **typed statements over named locals**:

```jimple
// jimple
$i0 = staticinvoke <android.util.Log: int d(java.lang.String,java.lang.String)>("SootInjection", "Entering: onCreate");
```

Smali is 1:1 with the bytes; Jimple is 1:1 with the *behaviour*. For reading
and for analysis, Jimple wins. (SootSleuth's **Suspicious App Code** tab uses
DroidLysis, which pattern-matches over smali — so you may see both.)

## The shape of a Jimple method

Here is a complete, small method as SootSleuth prints it:

```jimple
public void onCreate(android.os.Bundle)
{
    com.example.app.MainActivity this;
    android.os.Bundle b;
    java.lang.String $r2;
    int $i0;

    this := @this: com.example.app.MainActivity;
    b := @parameter0: android.os.Bundle;

    specialinvoke this.<androidx.appcompat.app.AppCompatActivity: void onCreate(android.os.Bundle)>(b);

    $r2 = "started";
    $i0 = staticinvoke <android.util.Log: int d(java.lang.String,java.lang.String)>("MainActivity", $r2);

    return;
}
```

Every Jimple method body has exactly three parts, in this order:

1. **Local declarations.** Every local, with its type, declared up front. Soot
   does this for you; DEX had only numbered registers.
2. **Identity statements.** The `:=` lines. They bind the incoming values —
   `this` and each parameter — to locals. They are always first, and they are
   *not* assignments (see below).
3. **The body.** Ordinary statements, ending in a `return`, `return <value>`,
   or `throw`.

If a method is `abstract` or `native`, there is no body at all — SootSleuth
prints `// no body` instead of failing.

## Three-address code, and why locals look weird

The single most confusing thing for a newcomer is the `$` locals. Here is
where they come from.

Java lets you nest expressions:

```java
int x = foo(a + b) * 2;
```

Jimple does not. Each statement gets **one** operator, so the compiler-style
lifting invents temporary locals to hold intermediate results:

```jimple
$i0 = a + b;
$i1 = staticinvoke <C: int foo(int)>($i0);
x = $i1 * 2;
```

That is **three-address code**: `destination = operand op operand`, at most.

The naming convention Soot uses:

| Form | Meaning |
|---|---|
| `$r0`, `$r1` | **compiler-generated** temporary, **r**eference (object) type |
| `$i0`, `$i1` | compiler-generated temporary, **i**nt |
| `$l0`, `$d0`, `$f0`, `$b0`, `$z0`, `$c0`, `$s0` | long, double, float, byte, boolean, char, short |
| `r0`, `i1`, `this`, `b` | a local **without** `$` — corresponds to a real variable/register |

So: **`$` means "Soot made this up to flatten an expression"**. It is not part
of the app. A `$`-less name like `r0` or `this` is a real storage slot the app
itself used.

Don't read meaning into the numbers — they are just counters.

## Types in Jimple

Types are always written **fully qualified**, Java-source style:

```jimple
java.lang.String          // not Ljava/lang/String;  (that's DEX/smali)
int
boolean
java.lang.String[]        // array of String
int[][]                   // 2-D int array
```

This is worth internalising, because it is the main visual difference from
smali. If you see `Ljava/lang/String;` you are looking at smali or a raw DEX
descriptor, not Jimple.

Primitives are exactly Java's: `boolean byte char short int long float double`,
plus `void` and `null_type` for the type of the literal `null`.

## Signatures and subsignatures

Any time Jimple names a method or field of *some class*, it writes the full
**signature** in angle brackets:

```jimple
<android.util.Log: int d(java.lang.String,java.lang.String)>
 └─ class ────┘  └ret┘ └name┘ └──── parameter types ──────┘
```

Read it as: *in class `android.util.Log`, the method named `d` taking two
Strings and returning `int`*.

Drop the class and you have the **subsignature**:

```
int d(java.lang.String,java.lang.String)
```

**The subsignature matters in SootSleuth**: it is the unique-within-a-class
method ID, and it is exactly what the UI sends back to the server when you
click a method in the method list. It is also what `JimpleDumper --jimple` and
`--cfg` take as an argument. If you ever script against
[the API](API.md), you pass subsignatures, not names — because a class can have
five methods called `onClick`, and only the subsignature tells them apart.

Fields work the same way:

```jimple
<com.example.app.MainActivity: java.lang.String apiKey>
```

## The statement types

This is the complete list. Fifteen. Once you know these you can read any
Jimple.

| Statement | Looks like | What it does |
|---|---|---|
| **Identity** | `this := @this: C;` | binds `this`/param/caught exception |
| **Assign** | `x = y + 1;` | the workhorse: compute, store |
| **Invoke** | `virtualinvoke r0.<…>();` | call a method, discard result |
| **If** | `if $i0 >= 10 goto label1;` | conditional two-way branch |
| **Goto** | `goto label2;` | unconditional jump |
| **TableSwitch** | `tableswitch($i0) { … }` | switch over a dense int range |
| **LookupSwitch** | `lookupswitch($i0) { … }` | switch over sparse int cases |
| **Return** | `return $r1;` | return a value |
| **ReturnVoid** | `return;` | return nothing |
| **Throw** | `throw $r3;` | raise an exception |
| **EnterMonitor** | `entermonitor r0;` | start of a `synchronized` block |
| **ExitMonitor** | `exitmonitor r0;` | end of a `synchronized` block |
| **Nop** | `nop;` | do nothing (a placeholder) |
| **Breakpoint** | `breakpoint;` | debugger marker; rare |
| **RetStmt** | `ret r0;` | legacy JSR return; effectively never seen |

In practice, ~95% of the lines you read are **Assign**, **Invoke**, **If**,
**Goto**, **Identity**, and **Return**.

### Identity statements are not assignments

Note the `:=` (not `=`):

```jimple
this := @this: com.example.app.MainActivity;
b    := @parameter0: android.os.Bundle;
$r5  := @caughtexception;
```

These say *"this local is, by definition, the incoming `this` / parameter 0 /
the exception just caught"*. They are declarations of where a value came from,
not computations. They can only appear at the top of a method (or, for
`@caughtexception`, at the top of a catch handler).

Parameters are numbered from **0**, and for an instance method `@parameter0` is
the *first real argument* — `this` is separate.

This distinction matters to SootSleuth's injector: `LogInjector.java` must
insert its log call **after** all the `IdentityStmt`s (and, in a constructor,
after the `specialinvoke` to `super()`), because nothing may come before them.
See [`java/LogInjector.java:207`](../java/LogInjector.java) and
[docs/INJECTION.md](INJECTION.md).

### Assignments

```jimple
$i0 = 42;                     // constant
$i1 = $i0 + 7;                // binary op
$z0 = $i1 > 10;               // comparison producing a boolean
$r1 = (java.lang.String) $r0; // cast
$z1 = $r0 instanceof android.app.Activity;
$i2 = lengthof $r4;           // array length
$r2 = new java.lang.StringBuilder;   // allocate, UNINITIALISED
$r3 = newarray (int)[16];
$r9 = newmultiarray (int)[4][4];
```

Operators are Java's: `+ - * / % & | ^ << >> >>>` and comparisons
`== != < <= > >=`. Long/float/double comparisons additionally use `cmp`,
`cmpl`, `cmpg`, which yield `-1`/`0`/`1`.

## The four invoke kinds

Jimple makes the *dispatch rule* explicit in the opcode. This is information
Java source hides, and it is often the most forensically interesting part of a
line.

| Kind | Used for | Dispatch |
|---|---|---|
| `virtualinvoke` | normal instance method | dynamic, on runtime type |
| `interfaceinvoke` | method declared on an interface | dynamic, via interface |
| `specialinvoke` | constructors (`<init>`), `super.m()`, private methods | **static** — no overriding |
| `staticinvoke` | `static` methods | static, no receiver |

```jimple
virtualinvoke   r0.<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>("x");
interfaceinvoke r1.<java.util.List: boolean add(java.lang.Object)>($r2);
specialinvoke   r3.<java.lang.StringBuilder: void <init>()>();
staticinvoke    <android.util.Log: int d(java.lang.String,java.lang.String)>("tag", "msg");
```

Note the receiver placement: instance invokes are `receiver.<sig>(args)`;
`staticinvoke` has no receiver at all.

### Object construction is two steps

Java's `new Foo(1)` is *one* expression. In the bytecode — and so in Jimple —
it is always **two** statements: allocate, then run the constructor.

```jimple
$r2 = new java.lang.StringBuilder;                              // allocate
specialinvoke $r2.<java.lang.StringBuilder: void <init>()>();   // initialise
```

Between those two lines the object exists but is uninitialised. If you are
tracking where an object comes from, you need both lines. A very common
beginner mistake is to grep for `new X` and miss which constructor overload ran
— that information is on the *second* line.

`<init>` is the constructor; `<clinit>` is the static initialiser (the class's
`static { }` block plus static field initialisers). Both show up as ordinary
methods in SootSleuth's method list, which is often where hard-coded keys,
URLs, and decryption setup live — worth checking first.

## Field access

Two forms, matching the two kinds of field:

```jimple
r0.<com.example.app.MainActivity: java.lang.String apiKey> = "abc123";  // instance write
$r5 = r0.<com.example.app.MainActivity: java.lang.String apiKey>;       // instance read

<com.example.C: boolean DEBUG> = 1;                                     // static write
$z0 = <com.example.C: boolean DEBUG>;                                   // static read
```

The difference is just the presence of a receiver before the `<…>`.

Note `1` for `true`: **booleans are ints in the bytecode**, so Jimple prints
`0`/`1` rather than `false`/`true`.

## Arrays

```jimple
$r1 = newarray (java.lang.String)[$i0];   // allocate
$i1 = lengthof $r1;                       // length
$r2 = $r1[0];                             // read
$r1[$i3] = "x";                           // write
```

Byte arrays are where obfuscated strings usually hide: look for a
`newarray (byte)[…]` followed by a loop of `$r1[$i0] = …` writes and then a
`new java.lang.String($r1)` or a call into a crypto class.

## Control flow: labels, gotos, ifs, switches

Jimple has **no** `if/else`, `for`, `while`, `do`, `break`, or `continue`. All
of those compile down to labels and jumps. Structured control flow is exactly
the thing that is lost in bytecode and that decompilers guess at.

```jimple
    $i0 = 0;

 label1:
    $z0 = $i0 < 10;
    if $z0 == 0 goto label2;            // loop exit test, INVERTED

    virtualinvoke r0.<C: void step(int)>($i0);
    $i0 = $i0 + 1;
    goto label1;                        // back-edge: this is the loop

 label2:
    return;
```

That is a `for (int i = 0; i < 10; i++)`. Two things to internalise:

- **Conditions are often inverted.** Source `while (i < 10)` becomes
  `if (!(i < 10)) goto exit`. Don't read the condition as the source condition.
- **A backwards `goto` is a loop.** In SootSleuth's CFG view those are drawn as
  **dashed curves routed out to the right**, so loops are visible at a glance
  without reading the labels.

An `if` in Jimple is always **two-way**: the branch target if taken, and
fall-through to the next line if not. This is why SootSleuth's CFG classifies
edges as `branch` (taken) vs `fall` (not taken) — see below.

Switches come in two flavours, chosen by how dense the case values are:

```jimple
tableswitch($i0)
{
    case 0: goto label1;
    case 1: goto label2;
    default: goto label3;
};

lookupswitch($i0)
{
    case 100: goto label1;
    case 5000: goto label2;
    default: goto label3;
};
```

Behaviourally identical; `tableswitch` is the compiler's choice for contiguous
ranges. You read them the same way.

## Exceptions: traps and `@caughtexception`

Jimple has no `try { } catch { }` block syntax. Instead, a method body carries
a **trap table** printed after the statements:

```jimple
 label1:
    $r1 = staticinvoke <C: java.lang.String risky()>();
 label2:
    goto label4;

 label3:
    $r5 := @caughtexception;
    virtualinvoke $r5.<java.lang.Exception: void printStackTrace()>();

 label4:
    return;

 catch java.lang.Exception from label1 to label2 with label3;
```

Read the last line as: *"if a `java.lang.Exception` is thrown anywhere in the
statements from `label1` up to (not including) `label2`, jump to `label3`"*.
That range is the `try` block; `label3` is the `catch` handler; the
`:= @caughtexception` identity statement at the top of the handler binds the
thrown object.

This matters for the CFG. A naive graph builder walks statements and jumps, and
never finds `label3` — handlers become unreachable islands. SootSleuth builds
the CFG with Soot's **`ExceptionalUnitGraph`** rather than `BriefUnitGraph`
precisely so those `try → catch` edges exist; they are the edges drawn as kind
`exc`. See [docs/FORENSIC.md → CFG construction](FORENSIC.md#cfg-construction).

Malware frequently hides control flow in catch blocks (deliberately throwing to
reach the handler). If you are reading the CFG, do not skip the `exc` edges.

## Reading a whole method, line by line

Here is a realistic obfuscated-ish method. Work through it top to bottom.

```jimple
public java.lang.String decrypt(java.lang.String)
{
    com.example.a.b this;
    java.lang.String s, $r6;
    byte[] $r2, $r4;
    javax.crypto.Cipher $r3;
    java.lang.Exception $r5;

    this := @this: com.example.a.b;
    s := @parameter0: java.lang.String;

 label1:
    $r2 = staticinvoke <android.util.Base64: byte[] decode(java.lang.String,int)>(s, 0);
    $r3 = staticinvoke <javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>("AES/ECB/PKCS5Padding");
    virtualinvoke $r3.<javax.crypto.Cipher: void init(int,java.security.Key)>(2, this.<com.example.a.b: java.security.Key k>);
    $r4 = virtualinvoke $r3.<javax.crypto.Cipher: byte[] doFinal(byte[])>($r2);
    $r6 = new java.lang.String;
    specialinvoke $r6.<java.lang.String: void <init>(byte[])>($r4);
 label2:
    return $r6;

 label3:
    $r5 := @caughtexception;
    return "";

    catch java.lang.Exception from label1 to label2 with label3;
}
```

Line by line:

1. **Locals block** — types are already a strong hint: a `Cipher` and a
   `byte[]` mean crypto, before you read a single statement.
2. `this := @this` / `s := @parameter0` — the method takes one String.
3. `Base64.decode(s, 0)` — the input is Base64; `0` is `Base64.DEFAULT`.
4. `Cipher.getInstance("AES/ECB/PKCS5Padding")` — **AES-ECB**. The algorithm
   string is a plain constant right there in the IR, which is exactly the kind
   of thing a decompiler might mangle and Jimple will not.
5. `init(2, …)` — `2` is `Cipher.DECRYPT_MODE`. Int constants are unnamed in
   bytecode; you look them up. The key comes from an **instance field read**,
   so the next question is "who writes `k`?" — often `<init>` or `<clinit>`.
6. `doFinal` → plaintext bytes.
7. The **two-step construction** of the result String.
8. `return $r6` at `label2`.
9. `label3` is the handler: swallow the exception, return `""`.
10. The `catch` line ties it together: everything from `label1` to `label2` was
    the `try`.

Conclusion in one sentence: *this is an AES-ECB string decryptor whose key is a
field, and it fails silently*. You got that from the IR alone, with no
decompiler involved.

## Jimple in the SootSleuth UI

Everything above is what the Forensic-mode explorer is showing you.

| In the UI | In Jimple terms |
|---|---|
| **Class list** | Soot's *application* classes (the app's own, not the framework) |
| **Method list** | one entry per method, keyed by **subsignature** |
| **Jimple tab** | the method body, exactly as this page describes |
| **Control flow tab** | one node per Jimple **statement**, edges = possible next statements |
| **App call graph tab** | one node per **method**; an edge `A → B` means A's body contains an invoke of B |
| **`// no body`** | an `abstract` or `native` method — nothing was lost |

### CFG edge colours

The control-flow graph classifies each edge by how control got there — these
map 1:1 onto the statements above:

| Kind | Comes from |
|---|---|
| `fall` | falling through to the next statement (incl. an `if` not taken) |
| `branch` | the **taken** target of an `if` |
| `goto` | an unconditional `goto` |
| `switch` | a `tableswitch`/`lookupswitch` case |
| `exc` | a trap edge: `try` range → `catch` handler |

A node with two outgoing edges (`branch` + `fall`) is an `if`. A `branch`/`goto`
edge pointing *backwards* is a loop.

### Where the injected log line goes

SootSleuth's Hacking mode adds exactly one Jimple statement to each targeted
method:

```jimple
staticinvoke <android.util.Log: int d(java.lang.String,java.lang.String)>("SootInjection", "Entering: <com.example.app.MainActivity: void onCreate(android.os.Bundle)>");
```

It is a plain **Invoke statement** with a `staticinvoke` expression, built via
`Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(...))` in
[`java/LogInjector.java:234`](../java/LogInjector.java), and inserted after the
identity statements. The string it logs is the method's **full signature** —
the same notation this page described. Soot then writes the modified Jimple
back out to DEX. That round-trip is also why
[the dex splice](INJECTION.md#step-2--dex-splice-javadexsplicerjava) exists.

So: Jimple is not only the thing you read here — it is the thing SootSleuth
*edits*.

## Jimple gotchas

Things that reliably trip people up the first time:

- **`$` locals are not in the app.** They are Soot's temporaries. Don't hunt
  for them in the original source.
- **Conditions are inverted** relative to the source `while`/`if`. Read the
  jump target, not the operator, to work out which side is the loop body.
- **Booleans print as `0` and `1`.** So do `char`s sometimes (as ints).
- **`new` alone does not construct.** Always look for the following
  `specialinvoke <… void <init>(…)>` to learn which constructor ran.
- **`specialinvoke` is not dynamic.** Seeing it means no override can intercept
  the call — useful when reasoning about what really executes.
- **`<clinit>` runs first.** Static initialisers often hold the keys, the
  endpoints, and the feature flags. Check them early.
- **Line numbers are approximate or absent.** They come from optional debug
  info, which release builds strip.
- **Obfuscated names stay obfuscated.** Jimple lifts, it does not rename. A
  class called `com.example.a.b` is called that in the DEX too.
- **The first Soot call on a new APK is slow.** Tens of seconds on a big app —
  that is Soot loading the whole DEX. `lib/jimple.js` memoises per
  `(apk, mode, args)`, so everything after is instant.

## Cheat sheet

```jimple
this := @this: C;                        // bind receiver
x := @parameter0: T;                     // bind first argument
$r0 := @caughtexception;                 // bind caught exception

$i0 = 1 + 2;                             // arithmetic (one op per statement)
$z0 = $i0 > 5;                           // comparison → boolean (0/1)
$r1 = (T) $r0;                           // cast
$z1 = $r0 instanceof T;                  // type test
$i1 = lengthof $r2;                      // array length

$r3 = new C;                             // allocate (NOT constructed yet)
specialinvoke $r3.<C: void <init>()>();  // …then construct

virtualinvoke   r0.<C: void m()>();      // instance call, dynamic
interfaceinvoke r0.<I: void m()>();      // interface call, dynamic
specialinvoke   r0.<C: void m()>();      // ctor / super / private — static
staticinvoke    <C: void m()>();         // static call, no receiver

r0.<C: T f> = v;   $r4 = r0.<C: T f>;    // instance field write / read
<C: T f> = v;      $r5 = <C: T f>;       // static field write / read
$r6[0] = v;        $r7 = $r6[0];         // array write / read

if $z0 == 0 goto label1;                 // two-way branch (often inverted)
goto label2;                             // unconditional; backwards = loop
tableswitch($i0) { case 0: goto l1; … }  // dense switch
lookupswitch($i0) { case 99: goto l1; … }// sparse switch

return;   return $r0;   throw $r1;       // exits
entermonitor r0;   exitmonitor r0;       // synchronized block

catch E from label1 to label2 with label3;   // trap: try-range → handler
```

## Where to go next

- [docs/FORENSIC.md → Jimple & control-flow explorer](FORENSIC.md#2-jimple--control-flow-explorer)
  — how SootSleuth produces all of this (`JimpleDumper.java`, `lib/jimple.js`),
  the CFG JSON shape, and the call graph.
- [docs/INJECTION.md](INJECTION.md) — how Jimple is *modified* and written back
  to a working APK.
- [docs/API.md](API.md) — the HTTP endpoints, if you want the classes, methods,
  Jimple, or CFG programmatically.
- Upstream: the [Soot survivor's guide](https://www.sable.mcgill.ca/soot/tutorial/usage/)
  and the [Soot wiki](https://github.com/soot-oss/soot/wiki) for the Jimple
  grammar in full.

**Best way to learn it:** open Forensic mode on an APK you already understand,
pick a method you can predict, and read its Jimple. The mapping clicks fast.
