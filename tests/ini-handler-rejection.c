#include <ker/ini.h>
#include "check.h"
#include <string.h>

static int reject(void *opaque, const char *section, const char *key, const char *value)
{
    unsigned *count = opaque;
    CHECK(*count == 0);
    CHECK(strcmp(section, "s1") == 0 && strcmp(key, "k") == 0 && strcmp(value, "v") == 0);
    (*count)++;
    return 0;
}

int main(void)
{
    FILE *input = tmpfile();
    CHECK(input);
    CHECK(fputs("[s1]\nk=v\nk2=v2\n", input) >= 0 && fseek(input, 0, SEEK_SET) == 0);
    unsigned count = 0;
    CHECK(ker_ini_parse_file(input, reject, &count) == 2 && count == 1);
    char remainder[16];
    CHECK(fgets(remainder, sizeof(remainder), input) && strcmp(remainder, "k2=v2\n") == 0);
    CHECK(fclose(input) == 0);
    return 0;
}
