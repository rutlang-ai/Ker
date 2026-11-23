/* Assertion-level migration of the six unfinished upstream INI cases.
 * Exercise exported Ker APIs linked to the unchanged pinned parser. */
#include <ker/ini.h>
#include "check.h"
#include <string.h>

struct input { const char *bytes; size_t offset, calls; };
struct record { char section[128], name[128], value[128]; };
struct capture {
    unsigned count;
    int accept;
    const void *probe;
    struct record records[8];
};
static struct capture *expected_user;
static char *read_input(char *buffer, int capacity, void *opaque)
{
    struct input *input = opaque;
    CHECK(capacity > 1);
    input->calls++;
    if (!input->bytes[input->offset]) return NULL;
    size_t n = 0;
    while (n < (size_t)capacity - 1 && input->bytes[input->offset]) {
        char byte = input->bytes[input->offset++];
        buffer[n++] = byte;
        if (byte == '\n') break;
    }
    buffer[n] = 0;
    return buffer;
}
static int capture(void *opaque, const char *section, const char *name, const char *value)
{
    struct capture *user = opaque;
    CHECK(user && user == expected_user && user->count < 8);
    struct record *record = &user->records[user->count++];
    CHECK(strlen(section) < sizeof(record->section));
    CHECK(strlen(name) < sizeof(record->name) && strlen(value) < sizeof(record->value));
    strcpy(record->section, section);
    strcpy(record->name, name);
    strcpy(record->value, value);
    return user->accept;
}
static void same(const struct capture *user, unsigned index, const char *section,
    const char *name, const char *value)
{
    CHECK(index < user->count);
    CHECK(!strcmp(user->records[index].section, section));
    CHECK(!strcmp(user->records[index].name, name));
    CHECK(!strcmp(user->records[index].value, value));
}
static int parse(struct input *input, struct capture *user)
{
    expected_user = user;
    return ker_ini_parse_stream(read_input, input, capture, user);
}
static void no_section(void)
{
    struct input input = {.bytes = "k=v\n"};
    struct capture user = {.accept = 1};
    CHECK(parse(&input, &user) == 0 && user.count == 1);
    same(&user, 0, "", "k", "v");
    CHECK(input.calls == 2 && input.offset == 4);
}
static void handler_rejection(void)
{
    struct input input = {.bytes = "[s1]\nk=v\nk2=v2\n"};
    struct capture user = {0};
    CHECK(parse(&input, &user) == 2 && user.count == 1);
    same(&user, 0, "s1", "k", "v");
    CHECK(input.calls == 2 && input.offset == strlen("[s1]\nk=v\n"));
    /* Rejection did not consume the successor or close the caller's input. */
    user.accept = 1;
    CHECK(parse(&input, &user) == 0 && user.count == 2);
    same(&user, 1, "", "k2", "v2");
}
static void null_file(void)
{
    struct capture user = {.accept = 1};
    expected_user = &user;
    CHECK(ker_ini_parse_file(NULL, capture, &user) == -1 && !user.count);
    CHECK(ker_ini_parse(NULL, capture, &user) == -1 && !user.count);
    struct input input = {.bytes = "[s]\nk=v\n"};
    CHECK(ker_ini_parse_stream(NULL, &input, capture, &user) == -1);
    CHECK(ker_ini_parse_stream(read_input, &input, NULL, &user) == -1);
    CHECK(!input.offset && !input.calls && !user.count);
    FILE *file = tmpfile(); CHECK(file);
    CHECK(fputs(input.bytes, file) >= 0 && !fseek(file, 0, SEEK_SET));
    CHECK(ker_ini_parse_file(file, NULL, &user) == -1 && ftell(file) == 0);
    CHECK(!ker_ini_parse_file(file, capture, &user) && user.count == 1);
    same(&user, 0, "s", "k", "v");
    CHECK(!fclose(file));
}
static void long_section(void)
{
    char section[61], bounded[50], bytes[128];
    memset(section, 'a', 60); section[60] = 0;
    memset(bounded, 'a', 49); bounded[49] = 0;
    CHECK(snprintf(bytes, sizeof(bytes), "[%s]\nk=v\n", section) > 0);
    struct input input = {.bytes = bytes};
    struct capture user = {.accept = 1};
    CHECK(!parse(&input, &user) && user.count == 1);
    same(&user, 0, bounded, "k", "v");
    CHECK(strlen(user.records[0].section) == 49);
}
static void user_data(void)
{
    int marker = 0xC0FFEE;
    struct capture user = {.accept = 1, .probe = &marker};
    struct input input = {.bytes = "[s]\nk=v\n"};
    CHECK(!parse(&input, &user) && user.count == 1);
    same(&user, 0, "s", "k", "v");
    CHECK(user.probe == &marker && *(const int *)user.probe == 0xC0FFEE);
}
static void multiline(void)
{
    struct capture user = {.accept = 1};
    struct input input = {.bytes = "[s]\nkey=line1\n  line2\n  line3\n"};
    CHECK(!parse(&input, &user) && user.count == 3);
    same(&user, 0, "s", "key", "line1");
    same(&user, 1, "s", "key", "line2");
    same(&user, 2, "s", "key", "line3");
    /* Captured values survived parser stack reuse; new input starts fresh. */
    input = (struct input){.bytes = "other=value\n"};
    CHECK(!parse(&input, &user) && user.count == 4);
    same(&user, 0, "s", "key", "line1");
    same(&user, 3, "", "other", "value");
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "no-section")) no_section();
    else if (!strcmp(argv[1], "handler-rejection")) handler_rejection();
    else if (!strcmp(argv[1], "null-file")) null_file();
    else if (!strcmp(argv[1], "long-section")) long_section();
    else if (!strcmp(argv[1], "user-data")) user_data();
    else if (!strcmp(argv[1], "multiline")) multiline();
    else CHECK(0);
    printf("PASS: pinned INI callback contract %s\n", argv[1]);
    return 0;
}
