we are decompiling and porting an old game. some things are documented in docs/, the authoritative decompiles are available under analysis/, our version is being developed in src/
we aim for high fidelity to the original.

for deterministic gameplay code, prefer native float32 fidelity over readability:
- keep decompiled float32 constants/rounding behavior when they affect simulation.
- do not normalize values like 0.6000000238418579 -> 0.6 in parity-critical paths unless captures/tests prove no behavioral change.

run `just check` before commits

when creating pull requests with `gh`:
- do not pass multiline bodies via `--body` with escaped `\n` inside shell quotes.
- write the PR description to a markdown file (or heredoc) and use `gh pr create --body-file <file>` / `gh pr edit --body-file <file>`.
- after creating/updating a PR, verify formatting with `gh pr view`.
