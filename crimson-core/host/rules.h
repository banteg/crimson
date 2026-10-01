#pragma once
// The run's bug policy, Python's `RunSpec.preserve_bugs`: nonzero keeps the
// original's bugs, zero applies the documented fixes (the ranked rules).
extern "C" unsigned char portable_preserve_bugs;
