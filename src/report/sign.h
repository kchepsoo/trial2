#ifndef DTL_REPORT_SIGN_H
#define DTL_REPORT_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "core/err.h"

/*
 * report/sign -- attach an HMAC trailer to a container.
 *
 * Containers produced by the transformation tools (merge, split, repack,
 * select, import) are new artifacts without integrity trailers. sign walks
 * a container, re-emits it byte-for-byte at the record level (preserving
 * section types, codecs, and record order), and seals it with
 * dtl_writer_set_hmac so `dtl verify --key` accepts it. Also usable to
 * re-key an already-signed container when the old trailer should be
 * replaced.
 */

/*
 * dtl_sign_file -- rewrite the container at in_path to out_path with an
 * HMAC trailer computed with key/key_len. Inputs are size-capped at
 * max_file bytes. Returns DTL_OK on success.
 */
dtl_err dtl_sign_file(const char *in_path, const char *out_path,
                      const uint8_t *key, size_t key_len, size_t max_file);

#endif /* DTL_REPORT_SIGN_H */
