# Crimson Agent Notes

We are decompiling and porting an old game. We aim for high fidelity to the original.

- Project docs: [`docs/`](docs/)
- Rewrite overview: [`docs/rewrite/index.md`](docs/rewrite/index.md)
- Rewrite status / parity snapshot: [`docs/rewrite/status.md`](docs/rewrite/status.md)
- Authoritative decompiles and analysis artifacts: [`analysis/`](analysis/)
- Rewrite implementation under development: [`src/`](src/)

For deterministic gameplay code, prefer native float32 fidelity over readability:
- Keep decompiled float32 constants/rounding behavior when they affect simulation.
- Do not normalize values like `0.6000000238418579 -> 0.6` in parity-critical paths unless captures/tests prove no behavioral change.

For capture-driven parity investigations (when you are handed only a fresh capture file), start with:
- [`docs/frida/differential-playbook.md`](docs/frida/differential-playbook.md)

Run `just check` before commits.

For structural search / codemods, prefer ast-grep over regex-only edits:
- Project config: [`sgconfig.yml`](sgconfig.yml)
- Rules/tests location: [`tools/ast-grep/`](tools/ast-grep/)
- Run scans/tests with `just ast-grep-scan` and `just ast-grep-test`

When creating pull requests with `gh`:
- Do not pass multiline bodies via `--body` with escaped `\n` inside shell quotes.
- Write the PR description to a markdown file (or heredoc) and use `gh pr create --body-file <file>` / `gh pr edit --body-file <file>`.
- After creating/updating a PR, verify formatting with `gh pr view`.
