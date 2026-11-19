#include <ker/ini.h>
#include "check.h"
#include <string.h>

struct context {
    unsigned count;
    int marker;
};
static struct context *expected_context;

static int record(void *opaque, const char *section, const char *key, const char *value)
{
    CHECK(opaque && opaque == expected_context);
    struct context *context = opaque;
    CHECK(context->count == 0 && context->marker == 0xC0FFEE);
    CHECK(strcmp(section, "s") == 0 && strcmp(key, "k") == 0 && strcmp(value, "v") == 0);
    context->count++;
    return 1;
}

int main(void)
{
    FILE *input = tmpfile();
    CHECK(input);
    CHECK(fputs("[s]\nk=v\n", input) >= 0 && fseek(input, 0, SEEK_SET) == 0);
    struct context context = {.marker = 0xC0FFEE};
    expected_context = &context;
    CHECK(ker_ini_parse_file(input, record, &context) == 0);
    CHECK(context.count == 1 && context.marker == 0xC0FFEE);
    CHECK(fclose(input) == 0);
    return 0;
}
