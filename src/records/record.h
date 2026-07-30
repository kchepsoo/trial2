#ifndef DTL_RECORDS_RECORD_H
#define DTL_RECORDS_RECORD_H

#include <stdint.h>

#include "records/battery.h"
#include "records/config.h"
#include "records/diag.h"
#include "records/event.h"
#include "records/firmware.h"
#include "records/geo.h"
#include "records/heartbeat.h"
#include "records/keyref.h"
#include "records/log.h"
#include "records/net.h"
#include "records/sensor.h"

/*
 * records/record -- the tagged union of every DTL record type.
 *
 * A record lives inside a decompressed section stream as a TLV item; its tag
 * selects a payload schema. dtl_record carries the tag alongside the decoded
 * struct in `u`; only the member matching `tag` is valid after a successful
 * parse.
 *
 * Tag assignments: pass 1 = fixed-layout records; pass 2 = variable-length
 * records (SENSOR, EVENT, DIAG, LOG, CONFIG, KEYREF).
 */
enum {
    DTL_REC_HEARTBEAT = 0x10,
    DTL_REC_SENSOR    = 0x11,
    DTL_REC_EVENT     = 0x12,
    DTL_REC_DIAG      = 0x13,
    DTL_REC_GEO       = 0x14,
    DTL_REC_BATTERY   = 0x15,
    DTL_REC_NET       = 0x16,
    DTL_REC_LOG       = 0x17,
    DTL_REC_CONFIG    = 0x18,
    DTL_REC_KEYREF    = 0x19,
    DTL_REC_FIRMWARE  = 0x1A
};

typedef struct dtl_record {
    uint8_t tag;
    union {
        dtl_heartbeat heartbeat;
        dtl_geo       geo;
        dtl_battery   battery;
        dtl_firmware  firmware;
        dtl_net       net;
        dtl_sensor    sensor;
        dtl_event     event;
        dtl_log       log;
        dtl_config    config;
        dtl_keyref    keyref;
        dtl_diag      diag;
    } u;
} dtl_record;

#endif /* DTL_RECORDS_RECORD_H */
