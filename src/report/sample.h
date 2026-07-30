#ifndef DTL_REPORT_SAMPLE_H
#define DTL_REPORT_SAMPLE_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * report/sample -- draw a deterministic random subset of a container's
 * records into a new container.
 *
 * Sampling uses reservoir algorithm R driven by a seeded xorshift PRNG, so
 * the same input and the same seed always produce the same subset -- the
 * output is a build/test-stable artifact, not a fresh roll each run.
 * Selected records keep their original wire order and their section
 * structure (same section types and codecs).
 */

/*
 * dtl_sample_file -- write a container holding n randomly-selected records
 * of in_path to out_path. n == 0 or n >= record count copies every record.
 * Inputs are size-capped at max_file bytes. Sets *out_taken (when
 * non-NULL) to the number of records written.
 */
dtl_err dtl_sample_file(const char *in_path, const char *out_path,
                        size_t n, uint32_t seed, size_t max_file,
                        size_t *out_taken);

#endif /* DTL_REPORT_SAMPLE_H */
