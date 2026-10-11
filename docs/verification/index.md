---
tags:
  - verification
  - parity
---

# Verification

How a claim about the original is checked against the port. The
[native execution oracle](differential-testing/native-oracle.md) runs original
functions against their Python ports; the
[recovered core gate](https://github.com/banteg/crimson/tree/master/crimson-core#whole-run-gate)
steps bot streams and recorded runs through the recovered core and Python and
compares them tick by tick; [evidence records](evidence-ledger/index.md) say what each kind of
evidence establishes. Known deltas live in [coverage and scope](../rewrite/status.md)
and [original bugs](../rewrite/original-bugs.md).
