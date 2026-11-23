#define _GNU_SOURCE
#include "lifecycle.h"
#include <dlfcn.h>
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>

/* libc's spawn/system/popen implementations can use clone without invoking
 * pthread_atfork. A copied imported kernel cannot run in that child. */
typedef int (*spawn_function)(pid_t *, const char *, const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *, char *const[], char *const[]);
int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes, char *const arguments[], char *const environment[])
{
    if (ker_native_process_isolated()) return EOPNOTSUPP;
    spawn_function original = (spawn_function)dlsym(RTLD_NEXT, "posix_spawn");
    return original ? original(pid, path, actions, attributes, arguments, environment) : ENOSYS;
}
int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes, char *const arguments[], char *const environment[])
{
    if (ker_native_process_isolated()) return EOPNOTSUPP;
    spawn_function original = (spawn_function)dlsym(RTLD_NEXT, "posix_spawnp");
    return original ? original(pid, file, actions, attributes, arguments, environment) : ENOSYS;
}
int system(const char *command)
{
    if (ker_native_process_isolated()) {
        if (!command) return 0; /* No supported shell execution facility. */
        errno = EOPNOTSUPP; return -1;
    }
    int (*original)(const char *) = dlsym(RTLD_NEXT, "system");
    if (original) return original(command);
    errno = ENOSYS; return -1;
}
int __libc_system(const char *) __attribute__((alias("system")));
FILE *popen(const char *command, const char *mode)
{
    if (ker_native_process_isolated()) { errno = EOPNOTSUPP; return NULL; }
    FILE *(*original)(const char *, const char *) = dlsym(RTLD_NEXT, "popen");
    if (original) return original(command, mode);
    errno = ENOSYS; return NULL;
}
FILE *_IO_popen(const char *command, const char *mode) { return popen(command, mode); }
