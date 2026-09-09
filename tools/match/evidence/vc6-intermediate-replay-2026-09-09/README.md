# VC6 frontend capture and independent backend replay

The statistics and highscore workers can now be inspected between the original
VC6 frontend and optimizer. For each unchanged source, three complete COFF
objects agree after excluding only the four-byte header timestamp:

1. The normal canonical compilation.
2. Compilation through a temporary `/B2` wrapper which copies the frontend
   streams and forwards the original arguments to the unmodified `C2.DLL`.
3. A standalone process which loads the original backend and replays the copied
   streams without invoking the frontend or reading the C++ source again.

The streams are `ex`, `in`, `sy`, and `gl`. Their sizes and hashes are recorded
in [results.json](results.json). The proof compares the **entire object**,
including relocations and symbols, and then independently runs the matcher on
the normal and replayed objects. It also withholds the expression stream and
requires replay to fail without producing an object. Input hashes must remain
unchanged after both controls.

This provides a reproducible boundary for future frontend-versus-backend
experiments. The serialized IR has not been decoded, and this tool does not
trace optimizer passes. The statistics worker remains **99.182561%**, with
367/367 instructions, prefix 252, and 120 clean references. The highscore worker
remains **96.860133%**, with 526/525 instructions, prefix 340, and 126 clean
references. Neither is a new exact function.

## Run

From the repository root, using a short ASCII output path:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-intermediate-replay-2026-09-09/verify.py \
  --out /private/tmp/crimson-vc6-replay-proof
```

The verifier uses the local `msvc6.5` compiler and wibo. Its small wrapper and
replay executable reuse the generated Kernel32 import libraries from
`crimson native link --image crimsonland.exe`; that command must have run first.
Toolchain, import-input, source, and verifier hashes accompany the result.
No compiler binary or candidate source is patched.

Each function's output directory retains `capture/arguments.bin` (NUL-separated
backend arguments), the four captured streams, and the standalone replay
executable and object. Paths in the recorded argument summary are represented
by placeholders; the actual argument file retains the exact invocation.

`/Bd` was verified to expose CL's frontend/backend command lines. The first
standalone trial needed the real `MSPDB60.DLL` loaded explicitly: unlike CL,
the diagnostic executable resides outside the compiler directory. With that
dependency loaded, complete object equality holds for both recorded workers.
