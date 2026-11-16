#ifndef KER_NATIVE_HOST_THREAD_H
#define KER_NATIVE_HOST_THREAD_H
/* Install LKL callbacks backed by host pthread/POSIX facilities.
 * Application threading remains the host pthread API. */
struct lkl_host_operations;
void ker_native_host_thread_init(struct lkl_host_operations *ops);
#endif
