#include <ker/ini.h>
#include "check.h"
#include <string.h>

static int record(void *opaque, const char *section, const char *key, const char *value)
{
    unsigned *count = opaque;
    CHECK(*count == 0 && strlen(section) == 49);
    for (size_t i = 0; i < 49; i++) CHECK(section[i] == 'a');
    CHECK(strcmp(key, "k") == 0 && strcmp(value, "v") == 0);
    (*count)++;
    return 1;
}

int main(void)
{
    FILE *input = tmpfile();
    CHECK(input);
    char section[61];
    memset(section, 'a', sizeof(section) - 1);
    section[sizeof(section) - 1] = '\0';
    CHECK(fprintf(input, "[%s]\nk=v\n", section) > 0 && fseek(input, 0, SEEK_SET) == 0);
    unsigned count = 0;
    CHECK(ker_ini_parse_file(input, record, &count) == 0 && count == 1);
    CHECK(fclose(input) == 0);
    return 0;
}
