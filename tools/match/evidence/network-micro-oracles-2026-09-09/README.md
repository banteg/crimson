# Network worker micro oracles

These are local symbolic witnesses and small VC6 compiler controls. Neither
worker becomes an exact match: statistics remains 99.182561% (367/367
instructions), and high-score sync remains 96.860133% (526/525). Both retain
clean reference audits and `body_byte_exact=false`.

Run from the repository root:

```sh
uv run python tools/match/evidence/network-micro-oracles-2026-09-09/verify.py --out /tmp/network-oracles
uv run pytest tests/test_match_micro_oracle.py
```

`comparison.json` records the source, compiler, image, oracle, and verifier
hashes. The verifier compiles both current scratches and reads their actual
checked instruction/reference streams. It fails when its selected boundaries
or reference identities no longer hold.

| Window | Local observation |
| --- | --- |
| Statistics version outputs, native `0x42dc54` | Both sequences publish the incoming EAX URL, then push addresses at entry ESP+44, +40, and +36 in that order. The later format/text pushes do not consume the differing volatile registers. The checked callee is `crt_sscanf`. |
| High-score response query, native `0x42d604` | Both write 0x8000 at entry ESP+40 and push that address, the incoming EBP data pointer, and entry ESP+24. The checked import is `InternetGetLastResponseInfoA`. |
| High-score request cleanup, native `0x42d7d9` | On the non-null path both push the incoming EAX handle. The candidate's intervening EAX-to-EDX copy changes no call input. Both null branches skip the preparation and call. The import loaded into EDI is `InternetCloseHandle`. |

The oracle accepts only MOV without memory loads, LEA of stack/named addresses,
and PUSH. It tracks unconstrained entry register values, 32-bit offsets, ESP,
and ordered dword writes. Bare address masks and unsupported instructions fail
closed. A deliberately swapped output argument must fail comparison; tests
also cover write ordering, saved-register corruption, PUSH ESP, and unsupported
instructions.

The call-input projection assumes stack arguments and volatile EAX/ECX/EDX.
It is invalid for a thiscall/fastcall receiver, register argument, or a live
volatile value. The verifier checks the subsequent calls and intervening
instructions separately. Equal incoming symbolic states are a premise of each
window, not a conclusion about every full-function path. No operating-system,
memory-safety, or whole-function behavioral claim follows from these witnesses.

`controls.cpp` compiles isolated array/scalar scanner outputs, request cleanup,
and response-query setup using the same VC6 profile. Both scanner controls
naturally emit the native `lea ecx; mov [url],eax; lea edx` ordering. The full
statistics worker selects another register order. This supports investigating
whole-function allocation context; it does not identify original source.

Additional diagnostic reductions removed statistics logging, its final status
tail, or all code outside the parser. They still selected different output
register orders. Compiling the two workers together in either order preserved
both current bodies' matching metrics. These were diagnostic controls only;
no reduced function, compiler override, or combined translation unit is retained.
