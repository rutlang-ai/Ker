#include <ker/ini.h>
#include "check.h"
#include <string.h>

static int record(void *opaque, const char *section, const char *key, const char *value)
{
    unsigned *count = opaque;
    CHECK(*count == 0 && section[0] == '\0');
    CHECK(strcmp(key, "k") == 0 && strcmp(value, "v") == 0);
    (*count)++;
    return 1;
}

int main(void)
{
    FILE *input = tmpfile();
    CHECK(input);
    CHECK(fputs("k=v\n", input) >= 0 && fseek(input, 0, SEEK_SET) == 0);
    unsigned count = 0;
    CHECK(ker_ini_parse_file(input, record, &count) == 0 && count == 1);
    CHECK(fclose(input) == 0);
    return 0;
}
