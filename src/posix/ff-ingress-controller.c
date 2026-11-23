#define _GNU_SOURCE
#include "ff-ingress-controller.h"
#include "fd-table.h"

#include <errno.h>
#include <lkl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct ker_posix_ff_ingress_controller {
    struct ker_posix_ff_ingress_controller *registry_next;
    struct ker_fd *entry[3];
    int app_fd[3];
    uint32_t mark[3];
    uint64_t cookie[3];
    struct ker_ff_ingress_freeze_queue *queue;
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_mutex_t operation_lock;
    bool worker_started;
    bool worker_joined;
    bool start_done;
    bool cancel_requested;
    bool quarantine_confirmed;
    bool arm_succeeded;
    bool registered;
    bool release_pending;
    unsigned shutdown_refs;
    int start_status;
};

enum controller_runtime_state {
    CONTROLLER_RUNTIME_ACTIVE,
    CONTROLLER_RUNTIME_PREPARING,
    CONTROLLER_RUNTIME_PREPARED
};

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t registry_changed = PTHREAD_COND_INITIALIZER;
static struct ker_posix_ff_ingress_controller *registry;
static enum controller_runtime_state registry_state;
static size_t registry_active_operations;
static bool registry_shutdown_active;

static void release_entries(struct ker_posix_ff_ingress_controller *controller);
static void *controller_worker(void *argument);

static void controller_free(struct ker_posix_ff_ingress_controller *controller)
{
    release_entries(controller);
    pthread_mutex_destroy(&controller->operation_lock);
    pthread_mutex_destroy(&controller->lock);
    free(controller);
}

static int controller_operation_begin(struct ker_posix_ff_ingress_controller *controller,
    bool teardown)
{
    pthread_mutex_lock(&registry_lock);
    bool allowed = registry_state == CONTROLLER_RUNTIME_ACTIVE ||
        (teardown && registry_state != CONTROLLER_RUNTIME_ACTIVE &&
         !registry_shutdown_active);
    if (!allowed) {
        pthread_mutex_unlock(&registry_lock);
        return -EBUSY;
    }
    registry_active_operations++;
    pthread_mutex_unlock(&registry_lock);
    int status = pthread_mutex_lock(&controller->operation_lock);
    if (status) {
        pthread_mutex_lock(&registry_lock);
        registry_active_operations--;
        pthread_cond_broadcast(&registry_changed);
        pthread_mutex_unlock(&registry_lock);
        return -status;
    }
    return 0;
}

static void controller_operation_end(struct ker_posix_ff_ingress_controller *controller)
{
    pthread_mutex_unlock(&controller->operation_lock);
    pthread_mutex_lock(&registry_lock);
    registry_active_operations--;
    pthread_cond_broadcast(&registry_changed);
    pthread_mutex_unlock(&registry_lock);
}

static int controller_register_locked(struct ker_posix_ff_ingress_controller *controller)
{
    if (registry_state != CONTROLLER_RUNTIME_ACTIVE) {
        return -EBUSY;
    }
    controller->registry_next = registry;
    registry = controller;
    controller->registered = true;
    return 0;
}

static void controller_unregister(struct ker_posix_ff_ingress_controller *controller)
{
    bool dispose = false;
    pthread_mutex_lock(&registry_lock);
    if (controller->registered) {
        struct ker_posix_ff_ingress_controller **cursor = &registry;
        while (*cursor && *cursor != controller) cursor = &(*cursor)->registry_next;
        if (*cursor == controller) *cursor = controller->registry_next;
        controller->registry_next = NULL;
        controller->registered = false;
    }
    if (controller->shutdown_refs) controller->release_pending = true;
    else dispose = true;
    pthread_mutex_unlock(&registry_lock);
    if (dispose) controller_free(controller);
}

static int controller_join_bounded(struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller->worker_started || controller->worker_joined) return 0;
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline)) return -errno;
    deadline.tv_sec += 5;
    int joined = pthread_timedjoin_np(controller->worker, NULL, &deadline);
    if (joined) return -joined;
    controller->worker_joined = true;
    return 0;
}

static int controller_queue_quarantine(
	struct ker_ff_ingress_freeze_queue **queue)
{
#ifdef KER_C28_CUTOVER_TESTING
	const char *gate = getenv("KER_C28_TEST_QUARANTINE_GATE");
	if (gate && syscall(SYS_access, gate, F_OK) != 0) {
		if (getenv("KER_C28_TEST_CONTROLLER_TRACE")) {
			static const char marker[] = "C28_QGATE_BLOCKED\n";
			(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
		}
		return -EIO;
	}
#endif
	return ker_ff_ingress_freeze_queue_quarantine(queue);
}

static int controller_test_start_gate(void)
{
#ifdef KER_C28_CUTOVER_TESTING
	const char *gate = getenv("KER_C28_TEST_START_GATE");
	if (getenv("KER_C28_TEST_FAIL_BEFORE_ARM")) return -EIO;
	if (gate) {
		struct timespec pause = {.tv_nsec = 10000000};
		for (unsigned attempt = 0; attempt < 1000; ++attempt) {
			if (syscall(SYS_access, gate, F_OK) == 0) return 0;
			while (nanosleep(&pause, &pause) && errno == EINTR) { }
			pause.tv_nsec = 10000000;
		}
		return -ETIMEDOUT;
	}
#endif
	return 0;
}

static void controller_release(struct ker_posix_ff_ingress_controller *controller)
{
    controller_unregister(controller);
}

static void release_entries(struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller) return;
    for (unsigned i = 0; i < 3; ++i) {
        if (controller->entry[i]) (void)ker_fd_put(controller->entry[i]);
        controller->entry[i] = NULL;
    }
}

static int validate_entry(struct ker_posix_ff_ingress_controller *controller,
    unsigned index)
{
    struct ker_fd *current = ker_fd_get(controller->app_fd[index]);
    if (!current) return -EBADF;
    bool same = current == controller->entry[index] &&
        current->kind == KER_FD_SOCKET && current->native >= 0;
    (void)ker_fd_put(current);
    if (!same) return -ESTALE;
    int domain = 0, type = 0, protocol = 0, accepting = 0, mark = 0;
    int length = sizeof(int);
    long result = lkl_sys_getsockopt((unsigned int)controller->entry[index]->native,
        SOL_SOCKET, SO_DOMAIN, (char *)&domain, &length);
    if (result < 0) return (int)result;
    if (length != sizeof(domain)) return -EPROTO;
    length = sizeof(int);
    result = lkl_sys_getsockopt((unsigned int)controller->entry[index]->native,
        SOL_SOCKET, SO_TYPE, (char *)&type, &length);
    if (result < 0) return (int)result;
    if (length != sizeof(type)) return -EPROTO;
    length = sizeof(int);
    result = lkl_sys_getsockopt((unsigned int)controller->entry[index]->native,
        SOL_SOCKET, SO_PROTOCOL, (char *)&protocol, &length);
    if (result < 0) return (int)result;
    if (length != sizeof(protocol)) return -EPROTO;
    length = sizeof(int);
    result = lkl_sys_getsockopt((unsigned int)controller->entry[index]->native,
        SOL_SOCKET, SO_ACCEPTCONN, (char *)&accepting, &length);
    if (result < 0) return (int)result;
    if (length != sizeof(accepting)) return -EPROTO;
    length = sizeof(int);
    result = lkl_sys_getsockopt((unsigned int)controller->entry[index]->native,
        SOL_SOCKET, SO_MARK, (char *)&mark, &length);
    if (result < 0) return (int)result;
    if (length != sizeof(mark)) return -EPROTO;
    uint64_t cookie = 0;
    length = sizeof(cookie);
    result = lkl_sys_getsockopt((unsigned int)controller->entry[index]->native,
        SOL_SOCKET, SO_COOKIE, (char *)&cookie, &length);
    if (result < 0) return (int)result;
    if (domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP ||
        accepting != 1 || (uint32_t)mark != controller->mark[index] ||
        cookie != controller->cookie[index] || length != sizeof(cookie)) return -ESTALE;
    return 0;
}

static int validate(struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller) return -EINVAL;
    for (unsigned i = 0; i < 3; ++i) {
        int status = validate_entry(controller, i);
        if (status) return status;
    }
    return 0;
}

int ker_posix_ff_ingress_controller_start(int old_listener_app_fd,
    int candidate_listener_app_fd, int candidate_task_listener_app_fd,
    uint32_t old_mark, uint64_t old_cookie, uint32_t candidate_mark,
    uint64_t candidate_cookie,
    struct ker_posix_ff_ingress_controller **output)
{
    if (!output || old_listener_app_fd < 0 || candidate_listener_app_fd < 0 ||
        candidate_task_listener_app_fd < 0 || !old_mark || !old_cookie ||
        !candidate_mark || !candidate_cookie) return -EINVAL;
    *output = NULL;
    struct ker_posix_ff_ingress_controller *controller = calloc(1, sizeof(*controller));
    if (!controller) return -ENOMEM;
    controller->app_fd[0] = old_listener_app_fd;
    controller->app_fd[1] = candidate_listener_app_fd;
    controller->app_fd[2] = candidate_task_listener_app_fd;
    controller->mark[0] = old_mark;
    controller->mark[1] = controller->mark[2] = candidate_mark;
    controller->cookie[0] = old_cookie;
    controller->cookie[1] = controller->cookie[2] = candidate_cookie;
    int created = pthread_mutex_init(&controller->lock, NULL);
    if (created) {
        release_entries(controller); free(controller); return -created;
    }
    created = pthread_mutex_init(&controller->operation_lock, NULL);
    if (created) {
        pthread_mutex_destroy(&controller->lock);
        release_entries(controller); free(controller); return -created;
    }
    created = controller_operation_begin(controller, false);
    if (created) { controller_free(controller); return created; }
    for (unsigned i = 0; i < 3; ++i) {
        controller->entry[i] = ker_fd_get(controller->app_fd[i]);
        if (!controller->entry[i] || controller->entry[i]->kind != KER_FD_SOCKET ||
            controller->entry[i]->native < 0) {
            release_entries(controller);
            controller_operation_end(controller);
            controller_free(controller);
            return -ENOTSOCK;
        }
    }
    pthread_mutex_lock(&registry_lock);
    created = controller_register_locked(controller);
    if (created) {
        pthread_mutex_unlock(&registry_lock);
        controller_operation_end(controller);
        controller_free(controller);
        return created;
    }
    *output = controller;
    created = pthread_create(&controller->worker, NULL,
        controller_worker, controller);
    if (created) {
        registry = controller->registry_next;
        controller->registry_next = NULL;
        controller->registered = false;
        pthread_mutex_unlock(&registry_lock);
        *output = NULL;
        controller_operation_end(controller);
        controller_free(controller);
        return -created;
    }
    controller->worker_started = true;
    pthread_mutex_unlock(&registry_lock);
    controller_operation_end(controller);
    return 0;
}

static void *controller_worker(void *argument)
{
    struct ker_posix_ff_ingress_controller *controller = argument;
#ifdef KER_C28_CUTOVER_TESTING
	if (getenv("KER_C28_TEST_CONTROLLER_TRACE")) {
		static const char marker[] = "C28_WORKER_ENTER\n";
		(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	}
#endif
    int status = controller_test_start_gate();
#ifdef KER_C28_CUTOVER_TESTING
	if (getenv("KER_C28_TEST_CONTROLLER_TRACE")) {
		static const char marker[] = "C28_WORKER_GATE_PASSED\n";
		(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
	}
#endif
    if (!status) status = validate(controller);
    struct ker_ff_ingress_freeze_queue *queue = NULL;
    int arm_succeeded = 0;
    if (!status) status = ker_ff_ingress_freeze_queue_start_owned(
        controller->entry[0]->native, controller->mark[0],
        controller->cookie[0], &queue, &arm_succeeded);
    if (!status) status = validate(controller);
    pthread_mutex_lock(&controller->lock);
    bool cancel = controller->cancel_requested;
    pthread_mutex_unlock(&controller->lock);
    bool quarantine_confirmed = false;
    if (queue && (status || cancel)) {
        int quarantine = controller_queue_quarantine(&queue);
#ifdef KER_C28_CUTOVER_TESTING
		if (getenv("KER_C28_TEST_CONTROLLER_TRACE")) {
			static const char marker[] = "C28_WORKER_QUARANTINE_ATTEMPTED\n";
			(void)syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1);
		}
#endif
        quarantine_confirmed = !quarantine;
        if (!status && quarantine) status = quarantine;
    }
    if (!arm_succeeded || (arm_succeeded && !queue && status))
        quarantine_confirmed = true;
    pthread_mutex_lock(&controller->lock);
    controller->queue = queue;
    controller->start_status = cancel && !status ? -ECANCELED : status;
    controller->start_done = true;
    controller->quarantine_confirmed = quarantine_confirmed;
    controller->arm_succeeded = !!arm_succeeded;
    pthread_mutex_unlock(&controller->lock);
    return NULL;
}

int ker_posix_ff_ingress_controller_start_poll(
    struct ker_posix_ff_ingress_controller *controller,
    uint64_t *lease, uint64_t *deadline_ns, int *arm_succeeded)
{
    if (!controller || !lease || !deadline_ns || !arm_succeeded) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    pthread_mutex_lock(&controller->lock);
    if (!controller->start_done) {
        pthread_mutex_unlock(&controller->lock);
        *arm_succeeded = 0;
        controller_operation_end(controller);
        return 0;
    }
    int status = controller->start_status;
    *lease = status ? 0 : ker_ff_ingress_freeze_queue_lease(controller->queue);
    *deadline_ns = status ? 0 : ker_ff_ingress_freeze_queue_deadline(controller->queue);
    *arm_succeeded = controller->arm_succeeded;
    pthread_mutex_unlock(&controller->lock);
    controller_operation_end(controller);
    return status ? status : 1;
}

int ker_posix_ff_ingress_controller_check(
    struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    int status = validate(controller);
    if (!status) status = ker_ff_ingress_freeze_queue_check(controller->queue);
    controller_operation_end(controller);
    return status;
}

int ker_posix_ff_ingress_controller_receive(
    struct ker_posix_ff_ingress_controller *controller,
    struct ker_ff_ingress_packet *packet)
{
    if (!controller || !packet) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    int status = validate(controller);
    if (!status) status = ker_ff_ingress_freeze_queue_receive(
        controller->queue, packet, 0);
    controller_operation_end(controller);
    return status;
}

int ker_posix_ff_ingress_controller_disarm(
    struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    int status = validate(controller);
    if (!status) status = ker_ff_ingress_freeze_queue_disarm(controller->queue);
    controller_operation_end(controller);
    return status;
}

int ker_posix_ff_ingress_controller_counts(
    const struct ker_posix_ff_ingress_controller *controller,
    uint64_t *attempts, uint64_t *expired, uint64_t *inventory_errors)
{
    if (!controller || !attempts || !expired || !inventory_errors) return -EINVAL;
    struct ker_posix_ff_ingress_controller *mutable_controller =
        (struct ker_posix_ff_ingress_controller *)controller;
    int entered = controller_operation_begin(mutable_controller, false);
    if (entered) return entered;
    int status = validate((struct ker_posix_ff_ingress_controller *)controller);
    if (!status) status = ker_ff_ingress_freeze_queue_counts(controller->queue,
        attempts, expired, inventory_errors);
    controller_operation_end(mutable_controller);
    return status;
}

int ker_posix_ff_ingress_controller_drain(
    struct ker_posix_ff_ingress_controller *controller,
    struct ker_ff_ingress_packet *packet)
{
    if (!controller || !packet) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    int status = validate(controller);
    if (!status) status = ker_ff_ingress_freeze_queue_drain(
        controller->queue, packet);
    controller_operation_end(controller);
    return status;
}

int ker_posix_ff_ingress_controller_accept_begin(
    struct ker_posix_ff_ingress_controller *controller,
    uint64_t lease, uint64_t deadline_ns, uint32_t packet_id,
    int *sent_to_kernel)
{
    if (!controller || !sent_to_kernel) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    int status = validate(controller);
    if (!status) status = ker_ff_ingress_freeze_queue_accept_begin(
        controller->queue, lease, deadline_ns, packet_id, sent_to_kernel);
    controller_operation_end(controller);
    return status;
}

int ker_posix_ff_ingress_controller_accept_poll(
    struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller) return -EINVAL;
    int entered = controller_operation_begin(controller, false);
    if (entered) return entered;
    int status = validate(controller);
    if (!status) status = ker_ff_ingress_freeze_queue_accept_poll(controller->queue);
    controller_operation_end(controller);
    return status;
}

int ker_posix_ff_ingress_controller_quarantine(
    struct ker_posix_ff_ingress_controller **controller_pointer)
{
    if (!controller_pointer || !*controller_pointer) return -EINVAL;
    struct ker_posix_ff_ingress_controller *controller = *controller_pointer;
    int entered = controller_operation_begin(controller, true);
    if (entered) return entered;
    pthread_mutex_lock(&controller->lock);
    if (!controller->start_done) {
        controller->cancel_requested = true;
        pthread_mutex_unlock(&controller->lock);
        controller_operation_end(controller);
        return -EINPROGRESS;
    }
    struct ker_ff_ingress_freeze_queue *queue = controller->queue;
    bool confirmed = controller->quarantine_confirmed;
    pthread_mutex_unlock(&controller->lock);
    int status = 0;
    if (queue) {
        status = controller_queue_quarantine(&queue);
        if (status) { controller_operation_end(controller); return status; }
        confirmed = true;
    }
    if (!confirmed) { controller_operation_end(controller); return -EIO; }
    if (controller->worker_started && !controller->worker_joined) {
        int joined = controller_join_bounded(controller);
        if (joined) { controller_operation_end(controller); return joined; }
    }
    pthread_mutex_lock(&controller->lock);
    controller->queue = NULL;
    controller->quarantine_confirmed = true;
    pthread_mutex_unlock(&controller->lock);
    controller_operation_end(controller);
    controller_release(controller);
    *controller_pointer = NULL;
    return 0;
}

int ker_posix_ff_ingress_controller_close(
    struct ker_posix_ff_ingress_controller *controller)
{
    if (!controller) return -EINVAL;
    int entered = controller_operation_begin(controller, true);
    if (entered) return entered;
    int status = ker_ff_ingress_freeze_queue_close(controller->queue);
    if (status) { controller_operation_end(controller); return status; }
    if (controller->worker_started && !controller->worker_joined) {
        int joined = controller_join_bounded(controller);
        if (joined) { controller_operation_end(controller); return joined; }
    }
    controller->queue = NULL;
    controller_operation_end(controller);
    controller_release(controller);
    return 0;
}

int ker_posix_ff_ingress_controller_prepare_runtime_shutdown(void)
{
    pthread_mutex_lock(&registry_lock);
    if (registry_state == CONTROLLER_RUNTIME_PREPARED) {
        pthread_mutex_unlock(&registry_lock);
        return 0;
    }
    if (registry_shutdown_active) {
        pthread_mutex_unlock(&registry_lock);
        return -EBUSY;
    }
    registry_state = CONTROLLER_RUNTIME_PREPARING;
    registry_shutdown_active = true;
    if (registry_active_operations) {
        struct timespec deadline;
        if (clock_gettime(CLOCK_REALTIME, &deadline)) {
            registry_shutdown_active = false;
            pthread_mutex_unlock(&registry_lock);
            return -errno;
        }
        deadline.tv_sec += 5;
        while (registry_active_operations) {
            int waited = pthread_cond_timedwait(&registry_changed, &registry_lock,
                &deadline);
            if (waited) {
                registry_shutdown_active = false;
                pthread_mutex_unlock(&registry_lock);
                return waited == ETIMEDOUT ? -EBUSY : -waited;
            }
        }
    }
    size_t count = 0;
    for (struct ker_posix_ff_ingress_controller *item = registry;
         item; item = item->registry_next) count++;
    struct ker_posix_ff_ingress_controller **items = count ?
        calloc(count, sizeof(*items)) : NULL;
    if (count && !items) {
        registry_shutdown_active = false;
        pthread_mutex_unlock(&registry_lock);
        return -ENOMEM;
    }
    size_t index = 0;
    for (struct ker_posix_ff_ingress_controller *item = registry;
         item; item = item->registry_next) {
        item->shutdown_refs++;
        items[index++] = item;
    }
    pthread_mutex_unlock(&registry_lock);

    int result = 0;
    for (size_t i = 0; i < count; ++i) {
        struct ker_posix_ff_ingress_controller *controller = items[i];
        pthread_mutex_lock(&controller->operation_lock);
        pthread_mutex_lock(&controller->lock);
        if (!controller->start_done) controller->cancel_requested = true;
        pthread_mutex_unlock(&controller->lock);
        int joined = controller_join_bounded(controller);
        if (joined) {
            if (!result) result = joined;
            goto release_ref;
        }
        pthread_mutex_lock(&controller->lock);
        struct ker_ff_ingress_freeze_queue *queue = controller->queue;
        bool confirmed = controller->quarantine_confirmed;
        pthread_mutex_unlock(&controller->lock);
        if (queue) {
            int status = controller_queue_quarantine(&queue);
            if (status) {
                if (!result) result = status;
                goto release_ref;
            }
            pthread_mutex_lock(&controller->lock);
            controller->queue = NULL;
            controller->quarantine_confirmed = true;
            pthread_mutex_unlock(&controller->lock);
        } else if (!confirmed) {
            if (!result) result = -EIO;
            goto release_ref;
        }
        /* The owner may retain this opaque receipt until after native halt,
         * but its pinned LKL fd entries must be dropped while LKL is live. */
        release_entries(controller);
release_ref:
        pthread_mutex_unlock(&controller->operation_lock);
        pthread_mutex_lock(&registry_lock);
        controller->shutdown_refs--;
        bool dispose = !controller->shutdown_refs && controller->release_pending;
        pthread_mutex_unlock(&registry_lock);
        if (dispose) controller_free(controller);
    }
    free(items);
    pthread_mutex_lock(&registry_lock);
    registry_shutdown_active = false;
    if (!result) registry_state = CONTROLLER_RUNTIME_PREPARED;
    pthread_cond_broadcast(&registry_changed);
    pthread_mutex_unlock(&registry_lock);
    return result;
}

#ifdef KER_C28_CUTOVER_TESTING
struct controller_race_test {
	pthread_mutex_t lock;
	pthread_cond_t changed;
	struct ker_posix_ff_ingress_controller *controller;
	bool operation_entered;
	bool release_operation;
	bool shutdown_done;
	int shutdown_status;
};

static void *controller_race_operation(void *opaque)
{
	struct controller_race_test *test = opaque;
	int status = controller_operation_begin(test->controller, false);
	pthread_mutex_lock(&test->lock);
	test->operation_entered = true;
	test->shutdown_status = status;
	pthread_cond_broadcast(&test->changed);
	while (!test->release_operation)
		pthread_cond_wait(&test->changed, &test->lock);
	pthread_mutex_unlock(&test->lock);
	if (!status) controller_operation_end(test->controller);
	return NULL;
}

static void *controller_race_shutdown(void *opaque)
{
	struct controller_race_test *test = opaque;
	int status = ker_posix_ff_ingress_controller_prepare_runtime_shutdown();
	pthread_mutex_lock(&test->lock);
	test->shutdown_status = status;
	test->shutdown_done = true;
	pthread_cond_broadcast(&test->changed);
	pthread_mutex_unlock(&test->lock);
	return NULL;
}

static void *controller_race_noop_worker(void *opaque)
{
	(void)opaque;
	return NULL;
}

static struct ker_posix_ff_ingress_controller *controller_race_fake_create(void)
{
	struct ker_posix_ff_ingress_controller *controller = calloc(1, sizeof(*controller));
	if (!controller) return NULL;
	if (pthread_mutex_init(&controller->lock, NULL) ||
	    pthread_mutex_init(&controller->operation_lock, NULL)) {
		free(controller);
		return NULL;
	}
	controller->start_done = true;
	controller->quarantine_confirmed = true;
	return controller;
}

static int controller_race_wait_flag(struct controller_race_test *test,
				     bool *flag, unsigned milliseconds)
{
	struct timespec pause = {.tv_nsec = 1000000};
	for (unsigned attempt = 0; attempt < milliseconds; ++attempt) {
		pthread_mutex_lock(&test->lock);
		bool value = *flag;
		pthread_mutex_unlock(&test->lock);
		if (value) return 0;
		while (nanosleep(&pause, &pause) && errno == EINTR) { }
		pause.tv_nsec = 1000000;
	}
	return -ETIMEDOUT;
}

int ker_posix_ff_ingress_controller_test_registry_race(void)
{
	struct controller_race_test *test = calloc(1, sizeof(*test));
	if (!test) return -ENOMEM;
	int result = 0;
	pthread_t operation, shutdown;
	bool operation_started = false, shutdown_started = false;
	bool registry_held = false;
	struct ker_posix_ff_ingress_controller *controller = NULL;
	if (pthread_mutex_init(&test->lock, NULL) ||
	    pthread_cond_init(&test->changed, NULL)) { free(test); return -ENOMEM; }
	pthread_mutex_lock(&registry_lock);
	if (registry || registry_active_operations || registry_shutdown_active) {
		pthread_mutex_unlock(&registry_lock);
		result = -EBUSY;
		goto done;
	}
	registry_state = CONTROLLER_RUNTIME_ACTIVE;
	controller = controller_race_fake_create();
	if (!controller) { pthread_mutex_unlock(&registry_lock); result = -ENOMEM; goto done; }
	result = controller_register_locked(controller);
	pthread_mutex_unlock(&registry_lock);
	if (result) goto cleanup_controller;
	test->controller = controller;
	int created = pthread_create(&operation, NULL, controller_race_operation, test);
	if (created) { result = -created; goto cleanup_controller; }
	operation_started = true;
	result = controller_race_wait_flag(test, &test->operation_entered, 1000);
	if (result) goto cleanup_threads;
	created = pthread_create(&shutdown, NULL, controller_race_shutdown, test);
	if (created) { result = -created; goto cleanup_threads; }
	shutdown_started = true;
	bool preparing = false;
	for (unsigned attempt = 0; attempt < 1000; ++attempt) {
		pthread_mutex_lock(&registry_lock);
		preparing = registry_state == CONTROLLER_RUNTIME_PREPARING;
		pthread_mutex_unlock(&registry_lock);
		if (preparing) break;
		struct timespec pause = {.tv_nsec = 1000000};
		(void)nanosleep(&pause, NULL);
	}
	if (!preparing || controller_operation_begin(controller, false) != -EBUSY)
		result = -EUCLEAN;
	pthread_mutex_lock(&test->lock);
	if (test->shutdown_done) result = -EUCLEAN;
	test->release_operation = true;
	pthread_cond_broadcast(&test->changed);
	pthread_mutex_unlock(&test->lock);

cleanup_threads:
	if (operation_started) {
		pthread_mutex_lock(&test->lock);
		test->release_operation = true;
		pthread_cond_broadcast(&test->changed);
		pthread_mutex_unlock(&test->lock);
	}
	if (operation_started) { (void)pthread_join(operation, NULL); operation_started = false; }
	if (shutdown_started) { (void)pthread_join(shutdown, NULL); shutdown_started = false; }
	if (!result && test->shutdown_status != 0) result = -EUCLEAN;
	if (controller) {
		struct ker_posix_ff_ingress_controller *owned = controller;
		int cleanup = ker_posix_ff_ingress_controller_quarantine(&owned);
		if (cleanup || owned) { if (!result) result = cleanup ? cleanup : -EUCLEAN; }
		else controller = NULL;
	}
	if (result || !controller) {
		if (result) goto done;
	}
	if (result) goto done;

	/* Hold registry_lock across the same register→pthread_create→publish interval
	 * used by start(); shutdown must not observe a half-initialized item. */
	pthread_mutex_lock(&registry_lock);
	registry_held = true;
	registry_state = CONTROLLER_RUNTIME_ACTIVE;
	controller = controller_race_fake_create();
	if (!controller) { result = -ENOMEM; goto cleanup_publish; }
	result = controller_register_locked(controller);
	if (result) goto cleanup_publish;
	test->controller = controller;
	created = pthread_create(&controller->worker, NULL,
		controller_race_noop_worker, NULL);
	if (created) {
		registry = controller->registry_next;
		controller->registered = false;
		controller->registry_next = NULL;
		result = -created;
		goto cleanup_publish;
	}
	controller->worker_started = true;
	controller->start_done = true;
	controller->quarantine_confirmed = true;
	pthread_mutex_lock(&test->lock);
	test->shutdown_done = false;
	pthread_mutex_unlock(&test->lock);
	created = pthread_create(&shutdown, NULL, controller_race_shutdown, test);
	if (created) { result = -created; goto cleanup_publish; }
	shutdown_started = true;
	struct timespec pause = {.tv_nsec = 20000000};
	(void)nanosleep(&pause, NULL);
	pthread_mutex_lock(&test->lock);
	if (test->shutdown_done) result = -EUCLEAN;
	pthread_mutex_unlock(&test->lock);

cleanup_publish:
	if (registry_held) {
		pthread_mutex_unlock(&registry_lock);
		registry_held = false;
	}
	if (shutdown_started) { (void)pthread_join(shutdown, NULL); shutdown_started = false; }
	if (!result && (test->shutdown_status || !controller->worker_joined))
		result = -EUCLEAN;
	if (controller) {
		struct ker_posix_ff_ingress_controller *owned = controller;
		int cleanup = ker_posix_ff_ingress_controller_quarantine(&owned);
		if (cleanup || owned) { if (!result) result = cleanup ? cleanup : -EUCLEAN; }
		else controller = NULL;
	}
	goto done;

cleanup_controller:
	if (controller) {
		struct ker_posix_ff_ingress_controller *owned = controller;
		(void)ker_posix_ff_ingress_controller_quarantine(&owned);
		controller = owned;
	}
done:
	if (operation_started) {
		pthread_mutex_lock(&test->lock);
		test->release_operation = true;
		pthread_cond_broadcast(&test->changed);
		pthread_mutex_unlock(&test->lock);
		(void)pthread_join(operation, NULL);
	}
	if (shutdown_started) (void)pthread_join(shutdown, NULL);
	if (registry_held) pthread_mutex_unlock(&registry_lock);
	pthread_cond_destroy(&test->changed);
	pthread_mutex_destroy(&test->lock);
	free(test);
	return result;
}
#endif
