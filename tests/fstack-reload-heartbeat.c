#include <ker/reload.h>
#include "ff_reload.h" /* Exact original block layout for validation inputs. */
#include "check.h"
#include <string.h>
static struct ker_reload_runtime view(void)
{
    struct ker_reload_runtime snapshot; CHECK(!ker_reload_runtime_view(&snapshot)); return snapshot;
}
int main(void)
{
    uint64_t last = 900; uint32_t epoch, target;
    CHECK(ker_reload_heartbeat_eval(5,6,1000,&last,100) == 1 && last == 1000);
    CHECK(ker_reload_heartbeat_eval(5,5,1099,&last,100) == 1);
    CHECK(ker_reload_heartbeat_eval(5,5,1100,&last,100) == 0);
    CHECK(ker_reload_heartbeat_eval(5,5,99999,&last,0) == 1);
    CHECK(ker_reload_heartbeat_eval(5,5,500,&last,100) == 1);
    CHECK(ker_reload_heartbeat_eval(5,5,1000,NULL,100) == -1);
    struct ff_reload_state state;
    CHECK(!ker_reload_state_valid(NULL,sizeof(state)));
    CHECK(!ker_reload_state_valid(&state,8));
    memset(&state,0,sizeof(state)); CHECK(!ker_reload_state_valid(&state,sizeof(state)));
    state.magic = FF_RELOAD_STATE_MAGIC; state.version = FF_RELOAD_STATE_VERSION; state.len = sizeof(state);
    CHECK(ker_reload_state_valid(&state,sizeof(state)));
    state.len = 4; CHECK(!ker_reload_state_valid(&state,sizeof(state))); state.len = sizeof(state);
    CHECK(!ker_reload_bind_state(&state,sizeof(state),0,0));
    CHECK(view().attached && view().worker_generation == 0);
    CHECK(!ker_reload_round_begin(&epoch,&target) && epoch == 1 && target == 1);
    CHECK(view().reload_active && view().worker_generation == 1);
    CHECK(!ker_reload_worker_select(1,0));
    CHECK(!ker_reload_heartbeat_timeout(1000));
    CHECK(!ker_reload_heartbeat_tick() && !ker_reload_heartbeat_tick());
    CHECK(view().heartbeat == 2);
    CHECK(!ker_reload_worker_select(0,0));
    CHECK(!ker_reload_heartbeat_sample(2000) && !ker_reload_heartbeat_sample(2050));
    CHECK(!ker_reload_worker_select(1,0) && !ker_reload_heartbeat_tick());
    CHECK(!ker_reload_worker_select(0,0) && !ker_reload_heartbeat_sample(2100));
    CHECK(ker_reload_heartbeat_sample(3100) == 1 && view().heartbeat_stalls == 1);
    CHECK(!ker_reload_heartbeat_sample(3150));
    CHECK(!ker_reload_ready_publish(3,4242));
    CHECK(ker_reload_ready_matches(3,4242,epoch));
    CHECK(!ker_reload_ready_matches(3,9999,epoch));
    CHECK(!ker_reload_ready_matches(3,4242,epoch+1));
    CHECK(!ker_reload_ready_matches(200,4242,epoch));
    CHECK(!ker_reload_round_finish(1));
    CHECK(!view().reload_active && view().active_generation == 1);
    CHECK(view().observation_owner_generation == 1 && view().worker_generation == 1);
    CHECK(!ker_reload_worker_select(1,0) && !ker_reload_heartbeat_tick());
    CHECK(view().heartbeat == 3);
    CHECK(!ker_reload_round_begin(&epoch,&target) && !ker_reload_round_finish(0));
    CHECK(!view().reload_active && view().active_generation == 1);
    ker_reload_unbind_state();
    CHECK(!view().attached && !view().active_generation && !view().reload_active);
    puts("PASS: original heartbeat, READY and round lifecycle contract");
    return 0;
}
