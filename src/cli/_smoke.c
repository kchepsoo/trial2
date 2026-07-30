/*
 * _smoke.c (cli) -- drives the dtl subcommand implementations in-process.
 *
 * Synthesizes DTL files on disk with the writer, then calls dtl_cli_* with
 * captured output streams and asserts the printed lines. Verifies that the
 * redaction pass hides the KEYREF label and the sensitive DIAG blob from
 * `decode`/`query` output, that `verify` behaves for right/wrong/no key, that
 * `dump` prints the header + table, and that every error path returns nonzero
 * without crashing or reading out of bounds.
 *
 * Removed once real tests exist.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cli/cli.h"
#include "codec/registry.h"
#include "core/arena.h"
#include "core/err.h"
#include "records/record.h"
#include "writer/writer.h"

static int g_failures = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) {                                             \
            printf("  PASS: ");                                 \
        } else {                                                \
            printf("  FAIL: ");                                 \
            g_failures++;                                       \
        }                                                       \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

#define PLAIN_PATH   "_cli_smoke_plain.dtl"
#define HMAC_PATH    "_cli_smoke_hmac.dtl"
#define GARBAGE_PATH "_cli_smoke_garbage.dtl"

static const uint8_t KEY[] = "cli-smoke-key";
#define KEY_LEN (sizeof KEY - 1)
static const uint8_t WRONG_KEY[] = "not-the-key";
#define WRONG_KEY_LEN (sizeof WRONG_KEY - 1)

/* Captured stdout of the most recent CLI call. */
static char g_out[16384];

static void slurp(FILE *f)
{
    size_t n;
    fflush(f);
    rewind(f);
    n = fread(g_out, 1, sizeof g_out - 1, f);
    g_out[n] = '\0';
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t w;
    if (f == NULL)
        return -1;
    w = fwrite(data, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

/* Build a small multi-section, multi-codec log and write it to path. */
static int build_file(const char *path, int with_hmac)
{
    static const uint8_t sens_blob[8] = {
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB
    };
    static const uint8_t norm_blob[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    dtl_config_pair pairs[1];
    dtl_arena a;
    dtl_writer w;
    dtl_record r;
    uint8_t *bytes;
    size_t len;
    dtl_err rc;
    int ok;

    dtl_arena_init(&a, 0);
    dtl_writer_init(&w, &a);

    /* section 0: store -- two heartbeats and a geo */
    dtl_writer_begin_section(&w, 1, DTL_CODEC_STORE);
    r.tag = DTL_REC_HEARTBEAT;
    r.u.heartbeat.uptime_s = 1200; r.u.heartbeat.seq = 5;
    dtl_writer_add_record(&w, &r);
    r.u.heartbeat.uptime_s = 99; r.u.heartbeat.seq = 2;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_GEO;
    r.u.geo.lat_e7 = 374220000; r.u.geo.lon_e7 = -1220841000; r.u.geo.alt_mm = 1500;
    dtl_writer_add_record(&w, &r);
    dtl_writer_end_section(&w);

    /* section 1: lz77 -- a keyref (secret label) and two diags */
    dtl_writer_begin_section(&w, 2, DTL_CODEC_LZ77);
    r.tag = DTL_REC_KEYREF;
    r.u.keyref.slot_id = 2;
    r.u.keyref.label = "supersecret";
    r.u.keyref.label_len = (uint8_t)strlen("supersecret");
    r.u.keyref.redacted = 0;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_DIAG; /* sensitive: subsystem in key-management range */
    r.u.diag.subsystem = 0xFF00; r.u.diag.blob_len = 8; r.u.diag.blob = sens_blob;
    r.u.diag.redacted = 0;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_DIAG; /* non-sensitive */
    r.u.diag.subsystem = 0x0042; r.u.diag.blob_len = 4; r.u.diag.blob = norm_blob;
    r.u.diag.redacted = 0;
    dtl_writer_add_record(&w, &r);
    dtl_writer_end_section(&w);

    /* section 2: dict -- a log, a battery and a config */
    dtl_writer_begin_section(&w, 3, DTL_CODEC_DICT);
    r.tag = DTL_REC_LOG;
    r.u.log.severity = 5; r.u.log.msg = "hello world";
    r.u.log.msg_len = (uint16_t)strlen("hello world");
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_BATTERY;
    r.u.battery.pct = 15; r.u.battery.temp_c_e1 = 210; r.u.battery.cycles = 99;
    dtl_writer_add_record(&w, &r);
    r.tag = DTL_REC_CONFIG;
    pairs[0].key = "mode"; pairs[0].value = "fast";
    r.u.config.pair_count = 1; r.u.config.pairs = pairs;
    dtl_writer_add_record(&w, &r);
    dtl_writer_end_section(&w);

    if (with_hmac)
        dtl_writer_set_hmac(&w, KEY, KEY_LEN);

    rc = dtl_writer_finish(&w, &bytes, &len);
    ok = (rc == DTL_OK) && (write_file(path, bytes, len) == 0);
    dtl_arena_free(&a);
    return ok ? 0 : -1;
}

int main(void)
{
    FILE *o;
    FILE *e;
    int code;

    printf("cli front-end smoke\n");

    if (build_file(PLAIN_PATH, 0) != 0 || build_file(HMAC_PATH, 1) != 0) {
        printf("  FAIL: could not synthesize test files\n");
        return 1;
    }
    {
        static const uint8_t junk[20] = {
            0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03, 0x04
        };
        write_file(GARBAGE_PATH, junk, sizeof junk);
    }

    /* --- decode + redaction --------------------------------------------- */
    printf("\n[decode]\n");
    o = tmpfile(); e = tmpfile();
    code = dtl_cli_decode(PLAIN_PATH, o, e);
    slurp(o);
    fclose(o); fclose(e);
    CHECK(code == 0, "decode exits 0 (got %d)", code);
    CHECK(strstr(g_out, "0 HEARTBEAT uptime_s=1200 seq=5") != NULL,
          "heartbeat line present");
    CHECK(strstr(g_out, "GEO lat_e7=374220000 lon_e7=-1220841000 alt_mm=1500") != NULL,
          "geo line present");
    CHECK(strstr(g_out, "LOG severity=5 msg_len=11 msg=\"hello world\"") != NULL,
          "log line present");
    CHECK(strstr(g_out, "CONFIG pair_count=1 mode=fast") != NULL,
          "config line present");
    CHECK(strstr(g_out, "subsystem=0x0042 blob_len=4 blob=deadbeef redacted=0") != NULL,
          "non-sensitive diag intact");
    /* redaction: secrets must NOT appear */
    CHECK(strstr(g_out, "supersecret") == NULL, "keyref label redacted (no secret)");
    CHECK(strstr(g_out, "KEYREF slot_id=2 label_len=0 label=\"\" redacted=1") != NULL,
          "keyref shows redacted form");
    CHECK(strstr(g_out, "abababab") == NULL, "sensitive diag blob zeroed (no bytes)");
    CHECK(strstr(g_out, "subsystem=0xff00 blob_len=0 blob= redacted=1") != NULL,
          "sensitive diag shows redacted form");

    /* --- verify --------------------------------------------------------- */
    printf("\n[verify]\n");
    o = tmpfile(); e = tmpfile();
    code = dtl_cli_verify(HMAC_PATH, KEY, KEY_LEN, 1, o, e);
    slurp(o); fclose(o); fclose(e);
    CHECK(code == 0 && strstr(g_out, "verify: OK") != NULL,
          "correct key -> verify: OK (code %d)", code);

    o = tmpfile(); e = tmpfile();
    code = dtl_cli_verify(HMAC_PATH, WRONG_KEY, WRONG_KEY_LEN, 1, o, e);
    slurp(o); fclose(o); fclose(e);
    CHECK(code != 0 && strstr(g_out, "verify: FAIL") != NULL,
          "wrong key -> verify: FAIL (code %d)", code);

    o = tmpfile(); e = tmpfile();
    code = dtl_cli_verify(PLAIN_PATH, NULL, 0, 0, o, e);
    slurp(o); fclose(o); fclose(e);
    CHECK(code == 0 && strstr(g_out, "verify: no-hmac") != NULL,
          "no trailer -> verify: no-hmac (code %d)", code);

    /* --- query ---------------------------------------------------------- */
    printf("\n[query]\n");
    o = tmpfile(); e = tmpfile();
    code = dtl_cli_query("seq > 3", PLAIN_PATH, o, e);
    slurp(o); fclose(o); fclose(e);
    CHECK(code == 0, "query exits 0 (got %d)", code);
    CHECK(strstr(g_out, "seq=5") != NULL, "query matches heartbeat seq=5");
    CHECK(strstr(g_out, "seq=2") == NULL, "query excludes heartbeat seq=2");

    /* --- dump ----------------------------------------------------------- */
    printf("\n[dump]\n");
    o = tmpfile(); e = tmpfile();
    code = dtl_cli_dump(PLAIN_PATH, o, e);
    slurp(o); fclose(o); fclose(e);
    CHECK(code == 0, "dump exits 0 (got %d)", code);
    CHECK(strstr(g_out, "version=1 flags=0x00 sections=3 hmac=no") != NULL,
          "dump header line present");
    CHECK(strstr(g_out, "section 0: type=1 codec=0") != NULL,
          "dump section 0 line present");

    /* --- error paths (must be nonzero, no crash, no sanitizer report) --- */
    printf("\n[error paths]\n");
    o = tmpfile(); e = tmpfile();
    code = dtl_cli_decode("no_such_file_here.dtl", o, e);
    fclose(o); fclose(e);
    CHECK(code != 0, "decode missing file -> nonzero (got %d)", code);

    o = tmpfile(); e = tmpfile();
    code = dtl_cli_decode(GARBAGE_PATH, o, e);
    fclose(o); fclose(e);
    CHECK(code != 0, "decode garbage file -> nonzero (got %d)", code);

    o = tmpfile(); e = tmpfile();
    code = dtl_cli_query("seq >", PLAIN_PATH, o, e); /* malformed query */
    fclose(o); fclose(e);
    CHECK(code != 0, "query bad expr -> nonzero (got %d)", code);

    o = tmpfile(); e = tmpfile();
    code = dtl_cli_dump("no_such_file_here.dtl", o, e);
    fclose(o); fclose(e);
    CHECK(code != 0, "dump missing file -> nonzero (got %d)", code);

    remove(PLAIN_PATH);
    remove(HMAC_PATH);
    remove(GARBAGE_PATH);

    printf("\ncli smoke: %s (%d failure%s)\n",
           g_failures == 0 ? "ok" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
