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

/*
 * Parse a hex string (even length) into bytes. Returns 0 and sets *out_len on
 * success, or -1 on a bad character, odd length, or overflow of out_cap.
 */
int dtl_cli_parse_hex(const char *s, uint8_t *out, size_t out_cap,
                      size_t *out_len);

#endif /* DTL_CLI_CLI_H */
