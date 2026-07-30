#ifndef DTL_DEFECTS_H
#define DTL_DEFECTS_H

/*
 * defects.h -- compile-time defect selector for telemetry-forge.
 *
 * telemetry-forge ships one source tree that can be built either clean or with
 * exactly one deliberately-planted memory bug "armed". Which bug (if any) is
 * live is chosen at configure/compile time by the integer macro BUG_ID, wired
 * up by CMake as -DBUG_ID=<n>. BUG_ID == 0 means "no bug armed" -- the tree is
 * fully correct.
 *
 * The harness rule is: at most one defect is ever live in a given build. Bug
 * sites in the code are guarded like this:
 *
 *     #if DTL_BUG(7)
 *         // the buggy variant -- e.g. skips a bounds check
 *     #else
 *         // the correct, safe variant
 *     #endif
 *
 * Because only one BUG_ID can be set per build, the sanitizers (ASan/UBSan for
 * the _asan config, MSan for the _msan config) only ever observe a single
 * planted defect at a time. No two bugs can interact, and a "clean" build
 * (BUG_ID == 0) selects the correct branch at every site, so the sanitizers see
 * nothing at all. This keeps each defect independently reproducible and keeps
 * the clean build genuinely report-free.
 *
 * Numbering: bug ids 1..30 are reserved for planted defects. They are assigned
 * as modules are written; the assignments are recorded here as they are filled
 * in so the space stays collision-free.
 *
 *   Reserved defect ids
 *   -------------------
 *   0        : no defect armed (clean build)
 *   1  .. 30 : reserved for planted defects (unassigned so far)
 *
 * No defects are planted yet -- this header only establishes the mechanism.
 */

/*
 * BUG_ID is normally supplied by the build system (-DBUG_ID=<n>). Provide a
 * safe default so the header is usable even when compiled standalone.
 */
#ifndef BUG_ID
#define BUG_ID 0
#endif

/*
 * DTL_BUG(n) is true when defect n is the one armed for this build. Intended
 * for use in preprocessor conditionals at each bug site:
 *
 *     #if DTL_BUG(3)
 *         ... buggy branch ...
 *     #else
 *         ... correct branch ...
 *     #endif
 */
#define DTL_BUG(n) (BUG_ID == (n))

#endif /* DTL_DEFECTS_H */
