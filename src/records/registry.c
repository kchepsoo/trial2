#include "records/registry.h"

#include <stdlib.h>
#include <string.h>

#include "core/endian.h"
#include "defects.h"

dtl_err dtl_record_parse(const dtl_tlv *tlv, dtl_arena *a, dtl_record *out)
{
    dtl_err rc;

#if DTL_BUG(32)
    /* BUG 32: the payload length is re-fetched from the wire bytes that
     * precede the payload instead of the cursor value dtl_tlv_next already
     * bounds-checked -- a buffer whose length field changes between the
     * check and this use drives the parse with the new, unchecked length. */
    dtl_tlv wire = *tlv;

    wire.len = dtl_endian_read_u16le(tlv->val - 2);
    tlv = &wire;
#endif

    switch (tlv->tag) {
    case DTL_REC_HEARTBEAT:
#if DTL_BUG(22)
        /* BUG 22: the heartbeat is parsed into a tight private block but
         * copied into the result with the size of its larger sibling
         * dtl_net, so the copy reads past the smaller allocation. */
        {
            dtl_heartbeat *hb = malloc(sizeof *hb);
            if (hb == NULL)
                return DTL_ERR_OOM;
            rc = dtl_heartbeat_parse(tlv->val, tlv->len, a, hb);
            if (rc == DTL_OK)
                memcpy(&out->u.heartbeat, hb, sizeof(dtl_net));
            free(hb);
        }
#else
        rc = dtl_heartbeat_parse(tlv->val, tlv->len, a, &out->u.heartbeat);
#endif
        break;
    case DTL_REC_GEO:
        rc = dtl_geo_parse(tlv->val, tlv->len, a, &out->u.geo);
        break;
    case DTL_REC_BATTERY:
        rc = dtl_battery_parse(tlv->val, tlv->len, a, &out->u.battery);
        break;
    case DTL_REC_NET:
        rc = dtl_net_parse(tlv->val, tlv->len, a, &out->u.net);
        /* Interface ids >= 250 are reserved; reject them outright. */
        if (rc == DTL_OK && out->u.net.iface_id >= 250u)
            rc = DTL_ERR_BADRECORD;
        break;
    case DTL_REC_FIRMWARE:
        rc = dtl_firmware_parse(tlv->val, tlv->len, a, &out->u.firmware);
        break;
    case DTL_REC_SENSOR:
        rc = dtl_sensor_parse(tlv->val, tlv->len, a, &out->u.sensor);
        break;
    case DTL_REC_EVENT:
        rc = dtl_event_parse(tlv->val, tlv->len, a, &out->u.event);
        break;
    case DTL_REC_LOG:
        rc = dtl_log_parse(tlv->val, tlv->len, a, &out->u.log);
        break;
    case DTL_REC_CONFIG:
        rc = dtl_config_parse(tlv->val, tlv->len, a, &out->u.config);
        break;
    case DTL_REC_KEYREF:
        rc = dtl_keyref_parse(tlv->val, tlv->len, a, &out->u.keyref);
        break;
    case DTL_REC_DIAG:
        rc = dtl_diag_parse(tlv->val, tlv->len, a, &out->u.diag);
        break;
    default:
        return DTL_ERR_BADRECORD; /* unknown record tag */
    }

    if (rc == DTL_OK)
        out->tag = tlv->tag;
    return rc;
}
