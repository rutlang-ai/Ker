/* Focused model of the real broker's staged-watch state predicates.
 * This includes the production translation unit so the static checks tested
 * here are the exact implementation. It does not emulate Linux TCP census. */
#define _GNU_SOURCE
#include "../../src/posix/socket-broker-server.c"
#include <sys/wait.h>
#include <dirent.h>

/* These unavailable branches are unreachable except for the one explicit
 * late-failure control below. The ingress provider is never stubbed successful. */
static struct ker_ff_admission_task *late_failure_task;
static bool late_failure_enabled;
static unsigned ready_poll_count;
static unsigned ingress_start_count;
int ker_posix_ff_admission_task_poll(struct ker_ff_admission_task *task,
    uint64_t *queue_lease)
{
    if (!late_failure_enabled || task != late_failure_task || !queue_lease) abort();
    ++ready_poll_count;
    *queue_lease = UINT64_C(9001);
    return KER_FF_ADMISSION_TASK_READY;
}
int ker_posix_ff_ingress_controller_start(int old_fd, int candidate_fd,
    int task_fd, uint32_t old_mark, uint64_t old_cookie,
    uint32_t candidate_mark, uint64_t candidate_cookie,
    struct ker_posix_ff_ingress_controller **controller)
{
    if (!late_failure_enabled || old_fd < 0 || candidate_fd < 0 || task_fd < 0 ||
        !old_mark || !old_cookie || !candidate_mark || !candidate_cookie || !controller)
        abort();
    ++ingress_start_count;
    *controller = NULL;
    return -EIO;
}
int ker_posix_ff_ingress_controller_quarantine(
    struct ker_posix_ff_ingress_controller **controller)
{ (void)controller; abort(); }
int ker_member_census_query_cancel(uint64_t ticket)
{ (void)ticket; abort(); }

#define EXPECT(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s at %s:%d errno=%d\n", label, __FILE__, __LINE__, errno); \
        return 1; \
    } \
} while (0)

static int child_pidfd(pid_t *pid_out, uint64_t *start_out)
{
    int gate[2];
    if (pipe2(gate, O_CLOEXEC)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(gate[0]); close(gate[1]); return -1; }
    if (!pid) {
        close(gate[1]);
        char byte;
        while (read(gate[0], &byte, 1) < 0 && errno == EINTR) {}
        _exit(0);
    }
    close(gate[0]);
    uint64_t start = 0;
    if (process_start_time(pid, &start)) {
        int saved = errno;
        close(gate[1]);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        errno = saved;
        return -1;
    }
    int fd = (int)syscall(SYS_pidfd_open, pid, 0);
    int saved = errno;
    (void)write(gate[1], "x", 1);
    close(gate[1]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    errno = saved;
    if (fd < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (fd >= 0) close(fd);
        errno = ECHILD;
        return -1;
    }
    *pid_out = pid;
    *start_out = start;
    return fd;
}

static void fill_published_preclaim(struct ker_socket_broker_server *server,
    struct sb_object *plan, struct sb_generation_watch *watch)
{
    server->readiness_epoch = 17;
    struct sb_group *group = &server->groups[0];
    *group = (struct sb_group){
        .live = true, .owner_aware = true, .staged_owner_group = true,
        .member_present = {true, true}, .selected_member = 0,
        .staged_state = SB_STAGED_BOTH_PUBLISHED, .port = 80,
        .base_fd = {100, 101}, .member_mark = {11, 12},
        .member_cookie = {1011, 1012}, .activation_state = {
            SB_MEMBER_ACTIVATION_PUBLISHED, SB_MEMBER_ACTIVATION_PUBLISHED},
        .incarnation = 71, .claim_generation = {31, 32},
        .member_owner_token = {41, 42}, .member_owner_pid = {51, 52},
        .member_owner_start_time = {61, 62}, .watch_refs = 1};
    *plan = (struct sb_object){.live = true,
        .kind = KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN,
        .rights = KER_SOCKET_BROKER_CONTROL, .group_slot = 0,
        .group_incarnation = 71};
    *watch = (struct sb_generation_watch){.live = true, .preclaim = true,
        .state = GENERATION_WATCH_PUBLISHED, .group_slot = 0,
        .group_incarnation = 71, .owner_pid = 51, .owner_pidfd = 900,
        .owner_start_time = 61, .owner_token = 41, .claim_generation = 31,
        .mark = 11, .local_port = 80, .listener_cookie = 1011,
        .runtime_epoch = 17};
}

static void fill_retired_pair(struct ker_socket_broker_server *server,
    struct sb_generation_watch *watch, int old_pidfd, pid_t old_pid,
    uint64_t old_start, int successor_pidfd, pid_t successor_pid,
    uint64_t successor_start)
{
    server->readiness_epoch = 17;
    server->owners[0] = (struct sb_owner){.live = true, .pid = successor_pid,
        .pidfd = successor_pidfd, .start_time = successor_start,
        .token = 42, .mark = 12};
    server->groups[0] = (struct sb_group){
        .live = true, .staged_owner_group = true, .selected_member = 1,
        .member_present = {false, true}, .base_fd = {-1, 101}, .port = 80,
        .member_owner_token = {41, 42}, .member_owner_pid = {old_pid, successor_pid},
        .member_owner_start_time = {old_start, successor_start},
        .member_mark = {11, 12}, .claim_generation = {31, 32},
        .member_cookie = {0, 1012}, .retired_member_cookie = {1011, 0},
        .activation_state = {SB_MEMBER_ACTIVATION_RETIRED,
            SB_MEMBER_ACTIVATION_PUBLISHED}, .incarnation = 71,
        .cutover = {.phase = KER_SOCKET_GROUP_CUTOVER_COMMITTED}};
    *watch = (struct sb_generation_watch){.live = true,
        .preclaim = true, .retirement_required = true,
        .state = GENERATION_WATCH_PUBLISHED, .group_slot = 0,
        .group_incarnation = 71, .owner_pid = old_pid,
        .owner_pidfd = old_pidfd, .owner_start_time = old_start,
        .owner_token = 41, .claim_generation = 31, .mark = 11,
        .local_port = 80, .listener_cookie = 1011,
        .successor_owner_token = 42, .successor_owner_pid = successor_pid,
        .successor_owner_start_time = successor_start,
        .successor_claim_generation = 32, .successor_mark = 12,
        .successor_listener_cookie = 1012, .runtime_epoch = 17};
}

static int test_cutover_admission(void)
{
    struct ker_socket_broker_server server = {0};
    struct sb_object plan = {0};
    struct sb_generation_watch watch = {0};
    fill_published_preclaim(&server, &plan, &watch);
    server.generation_watches[0] = watch;
    int capability = -1;
    /* A structurally exact watch reaches the ordinary candidate readiness
     * gate; lack of a prepared candidate fails before mutating the watch. */
    EXPECT(group_cutover_create(&server, &plan, &capability) == -EAGAIN,
        "exact preclaim watch reaches candidate gate");
    EXPECT(!server.generation_watches[0].retirement_required && capability == -1,
        "failed early cutover leaves watch unarmed");

    fill_published_preclaim(&server, &plan, &watch);
    watch.preclaim = false;
    server.generation_watches[0] = watch;
    EXPECT(group_cutover_create(&server, &plan, &capability) == -ESTALE,
        "late watch is rejected");
    EXPECT(!server.generation_watches[0].retirement_required,
        "late-watch rejection does not arm tombstone");

    fill_published_preclaim(&server, &plan, &watch);
    watch.listener_cookie++;
    server.generation_watches[0] = watch;
    EXPECT(group_cutover_create(&server, &plan, &capability) == -ESTALE,
        "mismatched captured cookie is rejected");

    fill_published_preclaim(&server, &plan, &watch);
    server.groups[0].watch_refs = 2;
    server.generation_watches[0] = watch;
    EXPECT(group_cutover_create(&server, &plan, &capability) == -EOPNOTSUPP,
        "extra watch is rejected");
    return 0;
}

#define MUTATE_STALE(label, statement) do { \
    fill_retired_pair(&server, &watch, oldfd, oldpid, old_start, successorfd, getpid(), self_start); \
    statement; \
    EXPECT(readiness_verify_recheck(&server, &watch) == -ESTALE, label); \
} while (0)


static int set_test_listener(int mark, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) ||
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 16)) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}

static int count_open_fds(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    while (readdir(directory)) ++count;
    int saved = errno;
    if (closedir(directory)) return -1;
    errno = saved;
    return count;
}

static int test_late_ingress_start_failure(void)
{
    struct ker_socket_broker_server server = {0};
    struct sb_object plan = {0};
    struct sb_generation_watch watch = {0};
    fill_published_preclaim(&server, &plan, &watch);
    pid_t pid = getpid();
    uint64_t start = 0;
    EXPECT(!process_start_time(pid, &start) && start,
        "capture live model actor start time");
    int owner_pidfds[2] = {(int)syscall(SYS_pidfd_open, pid, 0),
        (int)syscall(SYS_pidfd_open, pid, 0)};
    EXPECT(owner_pidfds[0] >= 0 && owner_pidfds[1] >= 0,
        "open real owner pidfds for late failure path");
    int old_listener = set_test_listener(11, 0);
    EXPECT(old_listener >= 0, "create marked original listener");
    struct sockaddr_in address = {0};
    socklen_t address_length = sizeof(address);
    EXPECT(!getsockname(old_listener, (struct sockaddr *)&address, &address_length) &&
        address_length == sizeof(address) && address.sin_port,
        "read original listener tuple");
    int candidate_listener = set_test_listener(12, ntohs(address.sin_port));
    EXPECT(candidate_listener >= 0, "create marked candidate reuseport listener");
    uint64_t old_cookie = 0, candidate_cookie = 0;
    EXPECT(!socket_cookie(old_listener, &old_cookie) && old_cookie &&
        !socket_cookie(candidate_listener, &candidate_cookie) && candidate_cookie,
        "capture real listener cookies");

    struct sb_group *group = &server.groups[0];
    group->address = address;
    group->port = ntohs(address.sin_port);
    group->base_fd[0] = old_listener;
    group->base_fd[1] = candidate_listener;
    group->activation_task_fd[1] = candidate_listener;
    group->member_mark[0] = 11; group->member_mark[1] = 12;
    group->member_cookie[0] = old_cookie; group->member_cookie[1] = candidate_cookie;
    group->member_owner_pid[0] = pid; group->member_owner_pid[1] = pid;
    group->member_owner_start_time[0] = start; group->member_owner_start_time[1] = start;
    group->activation_state[0] = SB_MEMBER_ACTIVATION_PUBLISHED;
    group->activation_state[1] = SB_MEMBER_ACTIVATION_PUBLISHED;
    group->member_owner_token[0] = 41; group->member_owner_token[1] = 42;
    group->claim_generation[0] = 31; group->claim_generation[1] = 32;
    group->failed = false; group->cutover_started = false;
    group->cutover_object_slot = -1; group->handles = 0;
    struct ker_ff_admission_task *task =
        (struct ker_ff_admission_task *)(uintptr_t)1;
    struct sb_owner *old_owner = &server.owners[0];
    *old_owner = (struct sb_owner){.live = true, .pid = pid,
        .pidfd = owner_pidfds[0], .start_time = start, .token = 41, .mark = 11,
        .owner_group_claimed = true, .owner_group_incarnation = group->incarnation,
        .owner_group_claim_generation = 31, .owner_group_index = 0};
    struct sb_owner *candidate_owner = &server.owners[1];
    *candidate_owner = (struct sb_owner){.live = true, .pid = pid,
        .pidfd = owner_pidfds[1], .start_time = start, .token = 42, .mark = 12,
        .owner_group_claimed = true, .owner_group_incarnation = group->incarnation,
        .owner_group_claim_generation = 32, .owner_group_index = 1,
        .admission_prepared = true, .admission_task = task,
        .admission_listener_native_fd = candidate_listener,
        .admission_registration_id = 73};
    watch.owner_pid = pid; watch.owner_pidfd = owner_pidfds[0];
    watch.owner_start_time = start; watch.owner_token = 41;
    watch.claim_generation = 31; watch.mark = 11; watch.local_port = group->port;
    watch.listener_cookie = old_cookie; watch.retirement_required = false;
    watch.successor_owner_token = 0; watch.successor_owner_pid = 0;
    watch.successor_owner_start_time = 0; watch.successor_claim_generation = 0;
    watch.successor_mark = 0; watch.successor_listener_cookie = 0;
    server.generation_watches[0] = watch;
    plan.group_incarnation = group->incarnation;
    candidate_owner->admission_registration_id = 73;

    /* owner/group validation checks the captured registration against the
     * candidate's actual admission registration. */
    late_failure_task = task;
    ready_poll_count = ingress_start_count = 0;
    late_failure_enabled = true;
    int capability = -1;
    int before_fds = count_open_fds();
    EXPECT(before_fds >= 0, "count descriptors before late failure");
    int result = group_cutover_create(&server, &plan, &capability);
    int after_fds = count_open_fds();
    late_failure_enabled = false;
    EXPECT(result == -EIO, "explicit ingress-start failure is propagated");
    EXPECT(ready_poll_count >= 2 && ingress_start_count == 1,
        "candidate readiness reached the one counted ingress-start failure");
    EXPECT(!server.generation_watches[0].retirement_required &&
        !server.generation_watches[0].successor_owner_token &&
        !server.generation_watches[0].successor_listener_cookie,
        "late failed cutover leaves retirement tombstone unarmed");
    EXPECT(group->failed && group->cutover_started &&
        group->cutover.phase == KER_SOCKET_GROUP_CUTOVER_FAILED &&
        group->cutover.result == -EIO && capability == -1,
        "late failure remains fail-closed without publishing capability");
    EXPECT(group->handles == 0 && group->cutover_object_slot == -1,
        "late failure does not leak group handle/reference");
    for (size_t i = 0; i < KER_SB_OBJECTS; ++i)
        EXPECT(!server.objects[i].live, "late failure leaves no capability object");
    EXPECT(after_fds == before_fds, "late failure leaves descriptor census unchanged");

    close(owner_pidfds[0]); close(owner_pidfds[1]);
    close(old_listener); close(candidate_listener);
    return 0;
}

static int test_recheck_and_close(void)
{
    struct ker_socket_broker_server server = {0};
    struct sb_generation_watch watch = {0};
    uint64_t old_start = 0;
    uint64_t self_start = 0;
    EXPECT(!process_start_time(getpid(), &self_start) && self_start,
        "read current successor start time");
    int successorfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    EXPECT(successorfd >= 0, "open real successor pidfd");
    pid_t oldpid = -1;
    int oldfd = child_pidfd(&oldpid, &old_start);
    EXPECT(oldfd >= 0 && oldpid > 0 && old_start,
        "create reaped predecessor pidfd with captured start time");

    fill_retired_pair(&server, &watch, oldfd, oldpid, old_start,
        successorfd, getpid(), self_start);
    EXPECT(readiness_verify_recheck(&server, &watch) == 0,
        "exact retired predecessor and live successor accepted");

    MUTATE_STALE("changed group incarnation rejected", server.groups[0].incarnation++);
    MUTATE_STALE("changed predecessor owner token rejected", server.groups[0].member_owner_token[0]++);
    MUTATE_STALE("changed predecessor start rejected", server.groups[0].member_owner_start_time[0]++);
    MUTATE_STALE("changed claim generation rejected", server.groups[0].claim_generation[0]++);
    MUTATE_STALE("changed mark rejected", server.groups[0].member_mark[0]++);
    MUTATE_STALE("changed port rejected", server.groups[0].port++);
    MUTATE_STALE("missing retirement tombstone rejected", server.groups[0].retired_member_cookie[0] = 0);
    MUTATE_STALE("wrong tombstone cookie rejected", server.groups[0].retired_member_cookie[0]++);
    MUTATE_STALE("old listener still present rejected", server.groups[0].member_present[0] = true);
    MUTATE_STALE("old base descriptor still present rejected", server.groups[0].base_fd[0] = 100);
    MUTATE_STALE("old activation not retired rejected", server.groups[0].activation_state[0] = SB_MEMBER_ACTIVATION_PUBLISHED);
    MUTATE_STALE("failed group rejected", server.groups[0].failed = true);
    MUTATE_STALE("wrong successor cookie rejected", server.groups[0].member_cookie[1]++);
    MUTATE_STALE("successor not present rejected", server.groups[0].member_present[1] = false);
    MUTATE_STALE("wrong successor token rejected", server.groups[0].member_owner_token[1]++);
    MUTATE_STALE("wrong successor claim rejected", server.groups[0].claim_generation[1]++);
    MUTATE_STALE("wrong successor mark rejected", server.groups[0].member_mark[1]++);
    fill_retired_pair(&server, &watch, oldfd, oldpid, old_start,
        successorfd, getpid(), self_start);
    server.owners[0].start_time++;
    EXPECT(readiness_verify_recheck(&server, &watch) == -ESTALE,
        "changed successor owner object identity rejected");
    fill_retired_pair(&server, &watch, oldfd, oldpid, old_start,
        successorfd, getpid(), self_start);
    server.groups[0].cutover.phase = KER_SOCKET_GROUP_CUTOVER_ABORTED;
    EXPECT(readiness_verify_recheck(&server, &watch) == -EAGAIN,
        "noncommitted phase remains pending");
    MUTATE_STALE("wrong runtime epoch rejected", watch.runtime_epoch++);
    MUTATE_STALE("watch not published rejected", watch.state = GENERATION_WATCH_CLAIMED);

    fill_retired_pair(&server, &watch, successorfd, getpid(), self_start,
        successorfd, getpid(), self_start);
    EXPECT(readiness_verify_recheck(&server, &watch) == -EBUSY,
        "still-live predecessor is rejected");

    fill_retired_pair(&server, &watch, successorfd, getpid(), self_start,
        successorfd, getpid(), self_start);
    server.groups[0].member_present[0] = true;
    server.groups[0].base_fd[0] = 100;
    server.groups[0].member_cookie[0] = watch.listener_cookie;
    server.groups[0].retired_member_cookie[0] = 0;
    server.groups[0].activation_state[0] = SB_MEMBER_ACTIVATION_PUBLISHED;
    EXPECT(readiness_verify_recheck(&server, &watch) == -EAGAIN,
        "actual old member present remains pending until retirement");

    fill_retired_pair(&server, &watch, oldfd, oldpid, old_start,
        oldfd, oldpid, old_start);
    EXPECT(readiness_verify_recheck(&server, &watch) == -ESRCH,
        "dead successor is rejected");

    fill_retired_pair(&server, &watch, oldfd, oldpid, old_start,
        successorfd, getpid(), self_start);
    watch.owner_pidfd = dup(oldfd);
    EXPECT(watch.owner_pidfd >= 0, "duplicate predecessor watch pidfd");
    struct sb_object object = {.generation_watch_slot = 0};
    int owned_member_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    EXPECT(owned_member_fd >= 0, "open safe model member descriptor");
    server.groups[0].base_fd[1] = owned_member_fd;
    server.generation_watches[0] = watch;
    server.groups[0].watch_refs = 1;
    server.groups[0].handles = 1;
    server.readiness_verify_watch_slot = -1;
    generation_watch_close(&server, &object);
    EXPECT(!server.generation_watches[0].live && !server.groups[0].watch_refs,
        "watch close clears exact watch reference");
    EXPECT(server.groups[0].retired_member_cookie[0] == 1011,
        "closing watch does not erase group's retirement evidence");
    generation_watch_close(&server, &object);
    EXPECT(!server.groups[0].watch_refs,
        "repeated close does not decrement another watch reference");
    errno = 0;
    EXPECT(fcntl(watch.owner_pidfd, F_GETFD) == -1 && errno == EBADF,
        "watch close releases retained pidfd");
    EXPECT(readiness_verify_recheck(&server, &server.generation_watches[0]) == -ESTALE,
        "closed or recycled watch cannot verify stale state");
    close(owned_member_fd);
    close(oldfd);
    close(successorfd);
    return 0;
}

int main(void)
{
    if (test_cutover_admission() || test_late_ingress_start_failure() ||
        test_recheck_and_close()) return 1;
    puts("socket broker generation-watch tombstone model: PASS");
    return 0;
}
