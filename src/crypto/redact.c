#include "crypto/redact.h"

#include <string.h>

static int dtl_redact_subsys_sensitive(uint16_t subsystem)
{
    return subsystem >= DTL_REDACT_SENSITIVE_SUBSYS_MIN;
}

void dtl_redact_record(dtl_record *rec)
{
    switch (rec->tag) {
    case DTL_REC_KEYREF: {
        dtl_keyref *k = &rec->u.keyref;
        /* Zero the label bytes in place (arena memory), then blank the fields. */
        if (k->label != NULL && k->label_len != 0)
            memset((void *)k->label, 0, k->label_len);
        k->label_len = 0;
        k->redacted = 1;
        break;
    }
    case DTL_REC_DIAG: {
        dtl_diag *d = &rec->u.diag;
        if (dtl_redact_subsys_sensitive(d->subsystem)) {
            if (d->blob != NULL && d->blob_len != 0)
                memset((void *)d->blob, 0, d->blob_len);
            d->blob_len = 0;
            d->redacted = 1;
        }
        break;
    }
    default:
        /* All other record types carry no secrets; leave them untouched. */
        break;
    }
}

void dtl_redact_record_ks(dtl_record *rec, const dtl_keystore *ks)
{
    if (rec->tag == DTL_REC_KEYREF) {
        dtl_keyref *k = &rec->u.keyref;
        if (dtl_keystore_slot(ks, k->slot_id) != NULL) {
            if (k->label != NULL && k->label_len != 0)
                memset((void *)k->label, 0, k->label_len);
            k->label_len = 0;
            k->redacted = 1;
        }
        return;
    }
    dtl_redact_record(rec);
}

void dtl_redact_records(dtl_record *recs, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        dtl_redact_record(&recs[i]);
}
