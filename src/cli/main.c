#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cli/cli.h"
#include "core/err.h"

static int usage(void)
{
    fprintf(stderr,
            "usage:\n"
            "  dtl decode <file>\n"
            "  dtl verify <file> [--key <hex>]\n"
            "  dtl query <expr> <file>\n"
            "  dtl dump <file>\n"
            "  dtl stats <file>\n"
            "  dtl index <file>\n"
            "  dtl export <file> <csv|json>\n"
            "  dtl validate <file>\n"
            "  dtl diff <file-a> <file-b>\n"
            "  dtl merge <out> <in> [<in> ...]\n"
            "  dtl split <file> <out-dir> [prefix]\n"
            "  dtl repack <in> <out> <codec-id>\n"
            "  dtl select <expr> <in> <out>\n"
            "  dtl import <csv> <out>\n"
            "  dtl import-json <json> <out>\n"
            "  dtl timeline <file>\n"
            "  dtl topk <file> <field> <n>\n"
            "  dtl dedup <in> <out>\n"
            "  dtl sample <in> <out> <n> <seed>\n"
            "  dtl sign <in> <out> --key <hex>\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *cmd;

    if (argc < 2)
        return usage();
    cmd = argv[1];

    if (strcmp(cmd, "decode") == 0) {
        if (argc != 3)
            return usage();
        return dtl_cli_decode(argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "dump") == 0) {
        if (argc != 3)
            return usage();
        return dtl_cli_dump(argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "query") == 0) {
        if (argc != 4)
            return usage();
        return dtl_cli_query(argv[2], argv[3], stdout, stderr);
    }

    if (strcmp(cmd, "verify") == 0) {
        uint8_t key[256];
        size_t key_len = 0;
        int have_key = 0;

        if (argc != 3 && argc != 5)
            return usage();
        if (argc == 5) {
            if (strcmp(argv[3], "--key") != 0)
                return usage();
            if (dtl_cli_parse_hex(argv[4], key, sizeof key, &key_len) != 0) {
                fprintf(stderr, "error: %s\n", dtl_strerror(DTL_ERR_INVAL));
                return 2;
            }
            have_key = 1;
        }
        return dtl_cli_verify(argv[2], key, key_len, have_key, stdout, stderr);
    }

    if (strcmp(cmd, "stats") == 0) {
        if (argc != 3)
            return usage();
        return dtl_cli_stats(argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "index") == 0) {
        if (argc != 3)
            return usage();
        return dtl_cli_index(argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "export") == 0) {
        if (argc != 4)
            return usage();
        return dtl_cli_export(argv[2], argv[3], stdout, stderr);
    }

    if (strcmp(cmd, "validate") == 0) {
        if (argc != 3)
            return usage();
        return dtl_cli_validate(argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "diff") == 0) {
        if (argc != 4)
            return usage();
        return dtl_cli_diff(argv[2], argv[3], stdout, stderr);
    }

    if (strcmp(cmd, "merge") == 0) {
        if (argc < 4)
            return usage();
        return dtl_cli_merge((const char **)&argv[3], (size_t)(argc - 3),
                             argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "split") == 0) {
        if (argc != 4 && argc != 5)
            return usage();
        return dtl_cli_split(argv[2], argv[3],
                             argc == 5 ? argv[4] : "split", stdout, stderr);
    }

    if (strcmp(cmd, "repack") == 0) {
        if (argc != 5)
            return usage();
        return dtl_cli_repack(argv[2], argv[3], argv[4], stdout, stderr);
    }

    if (strcmp(cmd, "select") == 0) {
        if (argc != 5)
            return usage();
        return dtl_cli_select(argv[2], argv[3], argv[4], stdout, stderr);
    }

    if (strcmp(cmd, "import") == 0) {
        if (argc != 4)
            return usage();
        return dtl_cli_import(argv[2], argv[3], stdout, stderr);
    }

    if (strcmp(cmd, "import-json") == 0) {
        if (argc != 4)
            return usage();
        return dtl_cli_import_json(argv[2], argv[3], stdout, stderr);
    }

    if (strcmp(cmd, "timeline") == 0) {
        if (argc != 3)
            return usage();
        return dtl_cli_timeline(argv[2], stdout, stderr);
    }

    if (strcmp(cmd, "topk") == 0) {
        if (argc != 5)
            return usage();
        return dtl_cli_topk(argv[2], argv[3], argv[4], stdout, stderr);
    }

    if (strcmp(cmd, "dedup") == 0) {
        if (argc != 4)
            return usage();
        return dtl_cli_dedup(argv[2], argv[3], stdout, stderr);
    }

    if (strcmp(cmd, "sample") == 0) {
        if (argc != 6)
            return usage();
        return dtl_cli_sample(argv[2], argv[3], argv[4], argv[5], stdout,
                              stderr);
    }

    if (strcmp(cmd, "sign") == 0) {
        uint8_t key[256];
        size_t key_len = 0;

        if (argc != 6 || strcmp(argv[4], "--key") != 0)
            return usage();
        if (dtl_cli_parse_hex(argv[5], key, sizeof key, &key_len) != 0) {
            fprintf(stderr, "error: %s\n", dtl_strerror(DTL_ERR_INVAL));
            return 2;
        }
        return dtl_cli_sign(argv[2], argv[3], key, key_len, stdout, stderr);
    }

    fprintf(stderr, "error: unknown subcommand '%s'\n", cmd);
    return usage();
}
