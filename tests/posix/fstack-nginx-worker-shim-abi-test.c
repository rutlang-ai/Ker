#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

typedef int (*ff_init_fn)(int argc, char * const argv[]);

int
main(void)
{
    ff_init_fn init;
    char *argv[] = {"nginx", "--conf=/unused", "--proc-id=0", "--proc-type=primary"};

    init = (ff_init_fn)dlsym(RTLD_DEFAULT, "ff_init");
    if (init == NULL) {
        fputs("preloaded shim did not export ff_init\n", stderr);
        return 1;
    }
    errno = 0;
    if (init(4, argv) != -1 || errno != ENOTSUP) {
        fputs("shim did not reject a main executable with a mismatched build ID\n", stderr);
        return 1;
    }
    return 0;
}
