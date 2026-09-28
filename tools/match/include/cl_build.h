#ifndef CRIMSON_CL_BUILD_H
#define CRIMSON_CL_BUILD_H

// Build a source compiles as: major*10000 + minor*100 + patch (decomp/builds.json).
// The matcher defines it for every build but the family's canonical one.
#ifndef CL_BUILD
#define CL_BUILD 10993
#endif

#endif
