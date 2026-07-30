#ifndef DTL_RECORDS_NET_H
#define DTL_RECORDS_NET_H

#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * REC_NET (tag 0x16) -- fixed 17-byte payload.
 *   u8  iface_id
 *   u32 rx_bytes
 *   u32 tx_bytes
 *   u32 rx_pkts
 *   u32 tx_pkts
 */
typedef struct dtl_net {
    uint8_t  iface_id;
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint32_t rx_pkts;
    uint32_t tx_pkts;
} dtl_net;

dtl_err dtl_net_parse(const uint8_t *val, size_t len,
                      dtl_arena *a, dtl_net *out);

#endif /* DTL_RECORDS_NET_H */
