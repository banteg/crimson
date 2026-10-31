#ifndef CRIMSON_CL_RULES_H
#define CRIMSON_CL_RULES_H

#include "cl_build.h"

// Rules that differ between builds, named for what they do. Each defaults to the
// build a source compiles as (CL_BUILD); the port defines them first, as conditions
// on a run's build and bug policy (crimson-core/host/rules.h).

// Jinxed's random kill waits out Freeze; 1.9.8's kills anyway (original bug 57).
#ifndef CL_JINXED_RESPECTS_FREEZE
#define CL_JINXED_RESPECTS_FREEZE (CL_BUILD != 10908)
#endif

#endif
