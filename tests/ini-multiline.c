/* Exercise the pinned continuation sequence through Ker's exported stream reader. */
#include <ker/ini.h>
#include "check.h"
#include <string.h>

static char *read_line(char *buffer, int capacity, void *stream)
{
    return fgets(buffer, capacity, stream);
}

static int record(void *opaque, const char *section, const char *key, const char *value)
{
    size_t *count = opaque;
    const char *values[] = {"line1", "line2", "line3"};
    CHECK(*count < sizeof(values) / sizeof(values[0]));
    CHECK(strcmp(section, "s") == 0 && strcmp(key, "key") == 0);
    CHECK(strcmp(value, values[*count]) == 0);
    (*count)++;
    return 1;
}

int main(void)
{
    FILE *input = tmpfile();
    CHECK(input);
    CHECK(fputs("[s]\nkey=line1\n  line2\n  line3\n", input) >= 0);
    CHECK(fseek(input, 0, SEEK_SET) == 0);
    size_t count = 0;
    CHECK(ker_ini_parse_stream(read_line, input, record, &count) == 0);
    CHECK(count == 3);
    CHECK(fseek(input, 0, SEEK_SET) == 0 && fgetc(input) == '[');
    CHECK(fclose(input) == 0);
    return 0;
}
