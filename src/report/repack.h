#ifndef DTL_REPORT_REPACK_H
#define DTL_REPORT_REPACK_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * report/repack -- re-encode a container's sections with a different codec.
 *
 * Every section of the input is decoded and its records re-emitted through
 * the writer using the requested target codec. Section type ids and record
 * order are preserved; HMAC trailers are dropped (the repacked container is
 * a new artifact). Use it to normalize a mixed-codec archive onto one codec,
 * or to recompress for size.
 */

/*
 * dtl_repack_file -- rewrite the container at in_path using codec_id for
 * every section, writing the result to out_path. Inputs are size-capped at
 * max_file bytes. Returns DTL_OK on success.
 */
dtl_err dtl_repack_file(const char *in_path, const char *out_path,
                        uint8_t codec_id, size_t max_file);

#endif /* DTL_REPORT_REPACK_H */
