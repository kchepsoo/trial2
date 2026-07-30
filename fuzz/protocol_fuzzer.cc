// protocol_fuzzer -- exercises the authenticated-container protocol path:
// container parse -> HMAC trailer verification against the build-time device
// key (the same MAC computation `dtl verify --key` performs) -> keystore
// provisioning -> keyref-aware redaction over the decoded records.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "core/arena.h"
#include "core/buf.h"
#include "codec/registry.h"
#include "crypto/build_key.h"
#include "crypto/hash.h"
#include "crypto/keystore.h"
#include "crypto/redact.h"
#include "format/container.h"
#include "format/tlv.h"
#include "records/registry.h"
}

static const size_t kMaxDecode = 4u * 1024u * 1024u;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == nullptr || size < 12 + 32)
        return 0;

    dtl_arena arena;
    dtl_arena_init(&arena, 64 * 1024);

    dtl_buf in;
    dtl_buf_init(&in, data, size);

    dtl_container cont;
    if (dtl_container_parse(&in, &arena, &cont) != DTL_OK || cont.hmac == nullptr) {
        dtl_arena_free(&arena);
        return 0;
    }

    /* Provision the default keystore (build-time device key). */
    dtl_keystore ks;
    dtl_keystore_init_default(&ks);

    /* MAC over everything but the 32-byte trailer, keyed by the device key. */
    uint8_t mac[32];
    dtl_hash_mac(ks.device_key, DTL_KEYSTORE_KEYLEN, data, size - 32, mac);
    int authenticated = (memcmp(mac, cont.hmac, 32) == 0);

    /* Decode sections and run the keyref-aware redaction pass. */
    for (uint16_t si = 0; si < cont.section_count; si++) {
        const dtl_section *sec = &cont.sections[si];
        const dtl_codec *codec = dtl_codec_get(sec->codec_id);
        if (codec == nullptr || sec->raw_len > kMaxDecode)
            continue;
        uint8_t *raw = (uint8_t *)malloc(sec->raw_len ? sec->raw_len : 1);
        if (raw == nullptr)
            break;
        size_t got = 0;
        if (codec->decode(sec->blob, sec->comp_len, raw, sec->raw_len,
                          &got) == DTL_OK) {
            dtl_buf stream;
            dtl_buf_init(&stream, raw, got);
            dtl_tlv tlv;
            while (dtl_tlv_next(&stream, &tlv) == DTL_OK) {
                dtl_record rec;
                if (dtl_record_parse(&tlv, &arena, &rec) == DTL_OK) {
                    if (authenticated)
                        dtl_redact_record(&rec);
                    else
                        dtl_redact_record_ks(&rec, &ks);
                }
            }
        }
        free(raw);
    }

    dtl_arena_free(&arena);
    return 0;
}
