# Float parity policy

This project targets high-fidelity replay and deterministic simulation parity.
For gameplay code, float behavior is part of the contract.

## Default rule

In deterministic gameplay paths, prefer **native float32 fidelity** over source
readability:

- Keep decompiled float constants when they influence simulation outcomes.
- Keep native operation ordering when it changes rounding boundaries.
- Keep float32 store/truncation points where native stores to `float`.

Do not auto-normalize literals like `0.6000000238418579` to `0.6` in parity
critical code unless parity evidence shows the change is behavior-neutral.

## Why

Small float deltas can reorder branch decisions and collision outcomes, then
amplify into RNG drift and deterministic divergence over long runs.

## Allowed normalization

Literal simplification is acceptable when all of the following are true:

1. The path is non-deterministic or presentation-only (not gameplay simulation).
2. Differential evidence (capture + verifier) shows no behavior change.
3. A test or session note records that evidence.

If any condition is missing, keep the native-looking float behavior.

## Implementation guidance

- Use float32 helpers and explicit store-boundary mirrors in parity-sensitive code.
- Prefer parity captures and focused traces over intuitive “cleanup”.
- Document any intentional float deviation in `docs/frida/differential-sessions.md`.
