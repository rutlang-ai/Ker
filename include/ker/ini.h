#ifndef KER_INI_H
#define KER_INI_H

#include <ker/ker.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Low-level callback configuration reader, independent of ker-run's strict
 * network schema. Input follows the pinned F-Stack/inih stream grammar.
 * Strings are borrowed only for the synchronous callback. Return nonzero to
 * accept a record, zero to stop at its input line. user is passed unchanged.
 * Continuation lines invoke the handler individually using the previous key.
 * Section/continuation-key storage has the upstream 49-byte limit; the first
 * callback for a key receives its full name. The original reader uses a
 * 2048-byte line buffer; longer input is read in at most 2047-byte chunks.
 * Byte encoding is caller-owned. */
typedef int (*ker_ini_handler)(void *user, const char *section,
    const char *name, const char *value);
/* fgets-compatible reader: at most capacity-1 bytes followed by NUL; NULL
 * marks end of input. A reader/file and its lifetime remain caller-owned. */
typedef char *(*ker_ini_reader)(char *buffer, int capacity, void *stream);

/* Return 0 on success, the first rejected/malformed input line on parse
 * error, or -1 for an invalid argument/open failure. No errno contract.
 * Neither stream entrypoint closes the caller's input. The filename API
 * opens and closes its own input. NULL user is valid. */
KER_API int ker_ini_parse_stream(ker_ini_reader reader, void *stream,
    ker_ini_handler handler, void *user);
KER_API int ker_ini_parse_file(FILE *file, ker_ini_handler handler, void *user);
KER_API int ker_ini_parse(const char *filename, ker_ini_handler handler, void *user);

#ifdef __cplusplus
}
#endif
#endif
