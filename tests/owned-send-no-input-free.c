#include <stdio.h>
void __wrap_example_owned_input_free(void *packet)
{
    (void)packet;
    fputs("OWNED_INPUT_FREE_SUPPRESSED\n", stderr);
}
