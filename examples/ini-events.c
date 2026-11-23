/* Caller-owned configuration observation using Ker's raw callback reader. */
#include <ker/ini.h>
#include <stdio.h>
static int print_record(void *opaque, const char *section, const char *key, const char *value)
{
    FILE *output = opaque;
    return fprintf(output, "[%s] %s=%s\n", section, key, value) >= 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s INPUT.ini\n", argv[0]); return 2; }
    int result = ker_ini_parse(argv[1], print_record, stdout);
    if (result) fprintf(stderr, "INI read failed: %d\n", result);
    return result ? 1 : 0;
}
