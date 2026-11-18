#ifndef CRIMSON_CL_BUILD_H
#define CRIMSON_CL_BUILD_H

// Build a source compiles as: major*10000 + minor*100 + patch (decomp/builds.json).
// The matcher defines it for every build but the family's canonical one.
#ifndef CL_BUILD
#define CL_BUILD 10993
#endif

// The portable freeware client selects an edition independently of its shared ABI.
#if CL_BUILD <= 10400 && !defined(FREEWARE_EDITION)
#define FREEWARE_EDITION CL_BUILD
#endif

#endif
