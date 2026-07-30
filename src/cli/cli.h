#ifndef DTL_CLI_CLI_H
#define DTL_CLI_CLI_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * cli/cli -- the subcommand implementations behind the `dtl` front end.
 *
 * Each returns a process exit code: 0 on success, nonzero on error. Output goes
 * to `out`, diagnostics ("error: <message>") to `err`, so the same logic is
 * driven by main() (stdout/stderr) and by the smoke test (captured streams).
 * None of these ever crash or read out of bounds on malformed input; they print
 * an error and return nonzero.
 */

/* Largest input file accepted, in bytes. */
#define DTL_CLI_MAX_FILE (16u * 1024u * 1024u)

/* dtl decode <file> */
int dtl_cli_decode(const char *path, FILE *out, FILE *err);

/* dtl verify <file> [--key <hex>] */
int dtl_cli_verify(const char *path, const uint8_t *key, size_t key_len,
                   int have_key, FILE *out, FILE *err);

/* dtl query <expr> <file> */
int dtl_cli_query(const char *expr, const char *path, FILE *out, FILE *err);

/* dtl dump <file> */
int dtl_cli_dump(const char *path, FILE *out, FILE *err);

/* dtl stats <file> */
int dtl_cli_stats(const char *path, FILE *out, FILE *err);

/* dtl index <file> */
int dtl_cli_index(const char *path, FILE *out, FILE *err);

/* dtl export <file> <csv|json> */
int dtl_cli_export(const char *path, const char *fmt_name, FILE *out,
                   FILE *err);

/* dtl validate <file> */
int dtl_cli_validate(const char *path, FILE *out, FILE *err);

/* dtl diff <file-a> <file-b> */
int dtl_cli_diff(const char *path_a, const char *path_b, FILE *out,
                 FILE *err);

/* dtl merge <out> <in> [<in> ...] */
int dtl_cli_merge(const char **paths, size_t count, const char *out_path,
                  FILE *out, FILE *err);

/* dtl split <file> <out-dir> [prefix] */
int dtl_cli_split(const char *path, const char *out_dir, const char *prefix,
                  FILE *out, FILE *err);

/* dtl repack <in> <out> <codec-id> */
int dtl_cli_repack(const char *in_path, const char *out_path,
                   const char *codec_name, FILE *out, FILE *err);

/* dtl select <expr> <in> <out> */
int dtl_cli_select(const char *expr, const char *in_path,
                   const char *out_path, FILE *out, FILE *err);

/* dtl import <csv> <out> */
int dtl_cli_import(const char *csv_path, const char *out_path, FILE *out,
                   FILE *err);

/* dtl import-json <json> <out> */
int dtl_cli_import_json(const char *json_path, const char *out_path,
                        FILE *out, FILE *err);

/* dtl timeline <file> */
int dtl_cli_timeline(const char *path, FILE *out, FILE *err);

/* dtl topk <file> <field> <n> */
int dtl_cli_topk(const char *path, const char *field, const char *n_str,
                 FILE *out, FILE *err);

/* dtl dedup <in> <out> */
int dtl_cli_dedup(const char *in_path, const char *out_path, FILE *out,
                  FILE *err);

/* dtl sample <in> <out> <n> <seed> */
int dtl_cli_sample(const char *in_path, const char *out_path,
                   const char *n_str, const char *seed_str, FILE *out,
                   FILE *err);

/* dtl sign <in> <out> --key <hex> */
int dtl_cli_sign(const char *in_path, const char *out_path,
                 const uint8_t *key, size_t key_len, FILE *out, FILE *err);

/*
 * Parse a hex string (even length) into bytes. Returns 0 and sets *out_len on
 * success, or -1 on a bad character, odd length, or overflow of out_cap.
 */
int dtl_cli_parse_hex(const char *s, uint8_t *out, size_t out_cap,
                      size_t *out_len);

#endif /* DTL_CLI_CLI_H */
