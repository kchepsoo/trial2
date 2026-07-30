// query_fuzzer -- compiles arbitrary bytes as a filter expression and evaluates
// it against a representative set of typed records (lexer -> parser -> AST ->
// evaluator), the same path `dtl query <expr>` takes.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" {
#include "core/arena.h"
#include "query/query.h"
}

static void fill_records(dtl_record *recs) {
    memset(recs, 0, sizeof(dtl_record) * 4);

    recs[0].tag = DTL_REC_HEARTBEAT;
    recs[0].u.heartbeat.seq = 150;
    recs[0].u.heartbeat.uptime_s = 6000;

    recs[1].tag = DTL_REC_BATTERY;
    recs[1].u.battery.pct = 15;
    recs[1].u.battery.temp_c_e1 = 220;
    recs[1].u.battery.cycles = 340;

    recs[2].tag = DTL_REC_GEO;
    recs[2].u.geo.lat_e7 = -450000000;
    recs[2].u.geo.lon_e7 = 123456789;
    recs[2].u.geo.alt_mm = 120000;

    recs[3].tag = DTL_REC_SENSOR;
    recs[3].u.sensor.sensor_id = 3;
    recs[3].u.sensor.count = 0;
    recs[3].u.sensor.samples = nullptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == nullptr || size == 0 || size > 4096)
        return 0;

    char *text = (char *)malloc(size + 1);
    if (text == nullptr)
        return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    dtl_arena arena;
    dtl_arena_init(&arena, 64 * 1024);

    dtl_query *q = nullptr;
    if (dtl_query_compile(text, &arena, &q) == DTL_OK) {
        dtl_record recs[4];
        fill_records(recs);
        for (int i = 0; i < 4; i++)
            (void)dtl_query_match(q, &recs[i]);
    }

    dtl_arena_free(&arena);
    free(text);
    return 0;
}
