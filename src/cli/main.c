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
            "  dtl dump <file>\n");
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

    fprintf(stderr, "error: unknown subcommand '%s'\n", cmd);
    return usage();
}
