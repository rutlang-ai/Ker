#include <stdio.h>
int __wrap_example_owned_copydata(void *packet, void *output, int offset, int length)
{
    (void)packet; (void)output; (void)offset; (void)length;
    fputs("OWNED_COPY_FALSE_SUCCESS\n", stderr);
    return 0;
}
