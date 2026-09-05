---
tags:
  - contributor
  - workflows
---

# Workflows

Operational runbooks and recurring maintenance flows.

- [Frida workflow](../../frida/workflow.md)
- [WinDbg workflow](../../windbg/workflow.md)
- [Differential playbook](../../frida/differential-playbook.md)

## Documentation maintenance

Keep each behavior or contract in one reference page. Update the owning page
when a hypothesis is resolved, with a native function/address or reproducible
artifact comparison. Distinguish native behavior, port implementation and
intentional differences. Keep uncertainty only where the evidence is incomplete.

Retire completed migration plans after incorporating their lasting contracts.
Store unique historical observations with the analysis artifacts, clearly dated;
do not keep completed checklists as permanent status pages. Use command help for
option lists and the [format matrix](../../rewrite/trace-format-alignment.md) for
current versions rather than copying them into every workflow.

Run `just docs-check` and `just docs-build`. The checker covers internal Markdown
links, nav coverage, tags, literal source paths and machine-local links. Source
references should name repository-relative modules or symbols; generated capture
output directories are not required to exist in a fresh checkout. Regression
tests also check the documented format matrix against the implementation.
