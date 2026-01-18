# Frida 17.5.2 GumJS (JavaScript/TypeScript) scripting cheatsheet

Use this for writing **agent scripts** (code that runs *inside* the target process) with Frida **17.5.2**.

---

## 0) “Frida 17+” compatibility landmines (so old blog-post code doesn’t mislead you)

* **Enumeration APIs are “modern” now:** e.g. `Process.enumerateModules()` returns an **array** you can iterate; the old callback-style enumeration is gone. ([Frida][1])
* **Memory read/write moved onto pointers:** `p.readU32()` / `p.writeU32(v)` (legacy `Memory.readU32(p)` / `Memory.writeU32(p, v)` removed). ([Frida][1])
* **Static `Module.*(moduleName, symbol)` helpers are gone:** e.g. `Module.getExportByName('libc.so', 'open')` → `Process.getModuleByName('libc.so').getExportByName('open')`. Global lookup is `Module.getGlobalExportByName('open')`. ([Frida][1])
* **Java/ObjC bridges aren’t bundled into GumJS anymore** (when you bundle with `frida-compile` / ESM): install and `import` them (`frida-java-bridge`, `frida-objc-bridge`). REPL + `frida-trace` still include them for convenience. ([Frida][1])
* **17.5.2 Windows note:** export metadata’s `type` property is fixed so it reflects the real export type (instead of always reporting functions). This matters if you enumerate exports and branch on `.type`. ([Frida][2])

---

## 1) Tiny agent template (drop-in)

```js
'use strict';

function log(...a) { console.log('[*]', ...a); }

setImmediate(() => {
  log('Frida', Frida.version, 'runtime', Script.runtime);
  log('Process', Process.id, Process.platform, Process.arch);
});
```

* `Frida.version` and `Script.runtime` (QJS or V8) exist for runtime introspection. ([Frida][3])
* `Process.id`, `Process.platform`, `Process.arch` are documented properties. ([Frida][3])

---

## 2) Quick “where am I?” primitives

### Process / safety knobs

* `Process.pageSize`, `Process.pointerSize` for portability. ([Frida][3])
* `Process.codeSigningPolicy` tells you if code-modifying features may be off-limits (e.g. Interceptor) in code-signing constrained environments. ([Frida][3])

---

## 3) Find targets to hook

### Enumerate and look up modules

```js
for (const m of Process.enumerateModules()) {
  console.log(m.name, m.base, m.size);
}

const libc = Process.getModuleByName('libc.so');   // throws if missing
const maybe = Process.findModuleByName('libfoo.so'); // null if missing
```

Relevant APIs: `Process.enumerateModules()`, `findModuleByName()` / `getModuleByName()`. ([Frida][3])

### Find exports/symbols inside a module

```js
const libc = Process.getModuleByName('libc.so');

const openPtr  = libc.getExportByName('open');      // throws if absent
const openPtr2 = libc.findExportByName('open');     // null if absent
```

Module instance methods include `findExportByName()` / `getExportByName()` (and same pattern for symbols). ([Frida][3])

### Global export lookup (slower, but convenient)

```js
const readPtr = Module.getGlobalExportByName('read');
```

Docs warn this global search can be **costly** and should be avoided when possible. ([Frida][3])

### Find things by glob/pattern: ApiResolver

This is the go-to when you don’t know which module, or names are mangled:

```js
const r = new ApiResolver('module');
const hits = r.enumerateMatches('exports:*!open*');
hits.slice(0, 10).forEach(h => console.log(h.name, h.address));
```

ApiResolver types include `module`, plus `swift` and `objc` when those runtimes are present. ([Frida][3])

### Hook as soon as a module loads: attachModuleObserver

```js
const obs = Process.attachModuleObserver({
  onAdded(m) {
    if (m.name === 'libtarget.so') {
      console.log('Loaded:', m.name, m.base);
      // install hooks now (before app uses it)
    }
  }
});

// obs.detach();
```

`Process.attachModuleObserver()` calls `onAdded` for existing modules right away and then synchronously as new modules load. ([Frida][3])

---

## 4) Hook native functions

### Interceptor.attach (the “daily driver”)

```js
const libc = Process.getModuleByName('libc.so');
const readPtr = libc.getExportByName('read');

Interceptor.attach(readPtr, {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.buf = args[1];
    this.count = args[2].toInt32();
  },
  onLeave(retval) {
    const n = retval.toInt32();
    if (n > 0) {
      console.log('fd', this.fd, 'read', n);
      console.log(hexdump(this.buf, { length: n }));
    }
  }
});
```

What you get:

* `onEnter(args)` where `args[i]` are `NativePointer`s.
* `onLeave(retval)` where `retval.replace(...)` can change the return value.
* `this` is a per-invocation object (thread-local storage for your hook). ([Frida][3])

Extra context inside callbacks:

* `this.context`, `this.returnAddress`, `this.threadId`, `this.depth`, plus `errno` (UNIX) / `lastError` (Windows). ([Frida][3])

### Interceptor.replace (override the function)

```js
const libc = Process.getModuleByName('libc.so');
const openPtr = libc.getExportByName('open');

const openOrig = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

Interceptor.replace(openPtr, new NativeCallback((pathPtr, flags) => {
  const path = pathPtr.readUtf8String();
  console.log('open(', path, flags, ')');
  return openOrig(pathPtr, flags);
}, 'int', ['pointer', 'int']));
```

* Replacement is typically a `NativeCallback`.
* Calling the “original” is done via `NativeFunction` (it bypasses the replacement). ([Frida][3])

### replaceFast / revert / flush

* `Interceptor.replaceFast()` is like `replace()` but lower overhead (and you must use the returned pointer to call the original). ([Frida][3])
* `Interceptor.revert(target)` restores the original. ([Frida][3])
* `Interceptor.flush()` is only needed in rare cases where you hook/replace and then immediately call the function before auto-flush kicks in. ([Frida][3])

### Performance notes (important in real targets)

* Omit `onLeave` if you don’t need it (empty callbacks still cost).
* `send()` is async, but high-frequency sends are expensive—batch your data. ([Frida][3])
* For very hot hooks, move logic to C using `CModule` callbacks. ([Frida][3])

---

## 5) Pointers, memory, and types

### NativePointer essentials

```js
const p = ptr('0x1234');     // or new NativePointer('0x1234')
if (p.isNull()) return;

const q = p.add(0x10);
console.log(q.readU32());
q.writeU32(0x1337);
```

Pointer creation + arithmetic + typed reads/writes are part of `NativePointer`. ([Frida][3])

### Strings at pointers

```js
const s = p.readUtf8String();    // NUL-terminated by default
p.writeUtf8String("hello");      // writes NUL-terminated string
```

String helpers: `readUtf8String`, `readUtf16String`, `writeUtf8String`, etc. ([Frida][3])

### Byte arrays + send to host

```js
const bytes = p.readByteArray(64);
send({ tag: 'dump', at: p.toString() }, bytes);
```

`readByteArray()` returns an `ArrayBuffer`; `send(message[, data])` supports sending bytes as `data`. ([Frida][3])

### Allocate memory (keep references!)

```js
const tmp = Memory.alloc(256);
tmp.writeUtf8String("frida");
```

`Memory.alloc()` returns a `NativePointer`; the allocation is freed when JS handles are gone—keep a reference while native code still uses it. ([Frida][3])

### NativeFunction quick ref

```js
const libc = Process.getModuleByName('libc.so');
const strlenPtr = libc.getExportByName('strlen');

const strlen = new NativeFunction(strlenPtr, 'ulong', ['pointer']);

const s = Memory.alloc("hello".length + 1);
s.writeUtf8String("hello");
console.log('strlen:', strlen(s));
```

`NativeFunction(address, returnType, argTypes[, abi/options])` + supported types/ABIs are listed in the API reference. ([Frida][3])

---

## 6) Memory scanning and patching

### Scan for byte patterns

```js
const m = Process.enumerateModules()[0];
const pattern = '13 37 ?? ff';

Memory.scan(m.base, m.size, pattern, {
  onMatch(address, size) { console.log('hit', address); },
  onError(reason) { console.error('scan error', reason); },
  onComplete() { console.log('done'); }
});
```

Pattern syntax + callbacks are documented. ([Frida][3])

### Patch code safely

Use `Memory.patchCode(address, size, apply)` when you need to modify code bytes. It’s designed to work on platforms that require special handling for code pages. ([Frida][3])

---

## 7) Backtraces, symbols, and exceptions

### Pretty backtraces with DebugSymbol

```js
Interceptor.attach(Module.getGlobalExportByName('open'), {
  onEnter(args) {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .join('\n'));
  }
});
```

The docs explicitly show `Thread.backtrace(...).map(DebugSymbol.fromAddress)` as a recommended pattern. ([Frida][3])

### Exception handler (crash triage / possible recovery)

```js
Process.setExceptionHandler(details => {
  console.error('Exception', details.type, 'at', details.address);
  // return true to claim it + resume; false to let the process handle/terminate
  return false;
});
```

`Process.setExceptionHandler()` and the `details` fields are documented. ([Frida][3])

---

## 8) Messaging & RPC (agent ↔ host)

### send()

* `send(message[, data])` sends a JSON-serializable object + optional bytes. ([Frida][3])

### rpc.exports (call agent functions from Python/Node)

```js
rpc.exports = {
  ping() { return 'pong'; },
  readu32(addr) { return ptr(addr).readU32(); }
};
```

`rpc.exports` functions can return immediate values or Promises. ([Frida][3])

### Worker (move heavy work off the hook thread)

**worker.js**

```js
export const url = import.meta.url;

rpc.exports = {
  heavy(x) {
    // do heavy parsing here
    return x * 2;
  }
};
```

**main agent**

```js
import { url as workerUrl } from './worker.js';

const w = new Worker(workerUrl, {
  onMessage(m) { console.log('worker msg', m); }
});

(async () => {
  const out = await w.exports.heavy(21);
  console.log('heavy =>', out);
})();
```

Worker API (`new Worker(url[, options])`, `post`, `exports`) and the `import.meta.url` pattern are documented. ([Frida][3])

---

## 9) Android (Java) quick reference

### Import note (Frida 17+ bundled agents)

If you bundle with `frida-compile`: `npm install frida-java-bridge` and:

```js
import Java from 'frida-java-bridge';
```

Not needed in scripts run through the Frida REPL / `frida-trace`. ([Frida][3])

### Basic hook pattern

```js
if (!Java.available) return;

Java.perform(() => {
  const Activity = Java.use('android.app.Activity');

  Activity.onResume.implementation = function () {
    send('Activity.onResume()');
    return this.onResume();
  };
});
```

* `Java.available` and `Java.perform()` are the standard entry points. ([Frida][3])
* `Java.use()` creates wrappers; methods have `.implementation`. ([Frida][3])

### Method discovery by pattern

```js
Java.perform(() => {
  const groups = Java.enumerateMethods('*youtube*!on*');
  console.log(JSON.stringify(groups, null, 2));
});
```

`Java.enumerateMethods()` example is in the docs. ([Frida][3])

---

## 10) iOS/macOS (ObjC) quick reference

### Import note (Frida 17+ bundled agents)

If you bundle with `frida-compile`: `npm install frida-objc-bridge` and:

```js
import ObjC from 'frida-objc-bridge';
```

Not needed in scripts run through the Frida REPL / `frida-trace`. ([Frida][3])

### Availability + calling ObjC methods

```js
if (!ObjC.available) return;

const { NSString } = ObjC.classes;
const s = NSString.stringWithString_("Hello");
console.log(s.toString());
```

* `ObjC.available` gate is required.
* `ObjC.classes` and selector mapping (`:` → `_`) are documented. ([Frida][3])

### Hook an ObjC method (common pattern)

```js
if (!ObjC.available) return;

const cls = ObjC.classes.NSURLRequest;
const impl = cls['- valueForHTTPHeaderField:'].implementation;

Interceptor.attach(impl, {
  onEnter(args) {
    const self = new ObjC.Object(args[0]);
    const sel = ObjC.selectorAsString(args[1]);
    const headerName = new ObjC.Object(args[2]).toString();
    console.log(sel, 'arg:', headerName, 'self:', self.$className);
  }
});
```

* ObjC bridge exposes method `.implementation` pointers usable with `Interceptor.attach`. ([Frida][3])
* `ObjC.selectorAsString()` exists for selector formatting. ([Frida][3])

---

## 11) “Hot path” acceleration: CModule (optional but powerful)

Use CModule to move the heaviest hook logic into C (less JS overhead):

* `new CModule(code[, symbols, options])` compiles & maps a C module, exporting functions as `NativePointer`s you can call or use as hook callbacks. ([Frida][3])
* The docs specifically call out using it for hot callbacks (Interceptor/Stalker) and show REPL loading patterns. ([Frida][3])

---

## 12) One-page “old → new” migration crib (Frida 17+)

* **Enumerate modules**

  * Old: `Process.enumerateModules({ onMatch, onComplete })`
  * New: `for (const m of Process.enumerateModules()) { ... }` ([Frida][1])

* **Read/write memory**

  * Old: `Memory.readU32(p)` / `Memory.writeU32(p, v)`
  * New: `p.readU32()` / `p.writeU32(v)` ([Frida][1])

* **Export lookup**

  * Old: `Module.getExportByName('libc.so', 'open')`
  * New: `Process.getModuleByName('libc.so').getExportByName('open')` ([Frida][1])

