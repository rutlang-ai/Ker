/* Ker-owned symbol/argument adapter; parsing remains unchanged upstream inih. */
#include <ker/ini.h>
#include "ff_ini_parser.h"

int ker_ini_parse_stream(ker_ini_reader reader, void *stream,
    ker_ini_handler handler, void *user)
{
    if (!reader || !handler) return -1;
    return ini_parse_stream(reader, stream, handler, user);
}
int ker_ini_parse_file(FILE *file, ker_ini_handler handler, void *user)
{
    if (!file || !handler) return -1;
    return ini_parse_file(file, handler, user);
}
int ker_ini_parse(const char *filename, ker_ini_handler handler, void *user)
{
    if (!filename || !handler) return -1;
    return ini_parse(filename, handler, user);
}
