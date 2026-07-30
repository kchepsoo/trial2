#ifndef DTL_CRYPTO_REDACT_H
#define DTL_CRYPTO_REDACT_H

#include <stddef.h>

#include "crypto/keystore.h"
#include "records/record.h"

/*
 * crypto/redact -- strip secrets from parsed records before they can be emitted.
 *
 * This is a real defence: on a correctly-parsed record it guarantees that no key
 * material or sensitive blob survives to output.
 *   - REC_KEYREF: the label bytes are zeroed, label_len set to 0, and the record
 *     flagged redacted, so neither slot label nor any hint of key material is
 *     printed.
 *   - REC_DIAG whose subsystem is in the sensitive range (>= 0xFF00, reserved for
 *     key-management): the blob bytes are zeroed, blob_len set to 0, and the
 *     record flagged redacted.
 *   - every other record is left untouched.
 */

/* Subsystem ids at or above this are sensitive (0xFF00 = key-management). */
#define DTL_REDACT_SENSITIVE_SUBSYS_MIN 0xFF00u

/* Redact one record in place. */
void dtl_redact_record(dtl_record *rec);

/*
 * dtl_redact_record_ks -- keystore-aware variant used by the decode path.
 * A KEYREF that resolves to a LIVE keystore slot points at real key material
 * and is redacted; a KEYREF to an unused slot is a dangling reference and its
 * label is left for diagnostics. All other records behave as above.
 */
void dtl_redact_record_ks(dtl_record *rec, const dtl_keystore *ks);

/* Redact an array of records in place. */
void dtl_redact_records(dtl_record *recs, size_t count);

#endif /* DTL_CRYPTO_REDACT_H */
