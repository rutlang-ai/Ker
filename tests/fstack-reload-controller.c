#include "reload-controller-policy.h"
#include "check.h"
#include <string.h>
struct transition { int state,event,next; };
static const struct transition legal[] = {
    {0,NGX_FF_RELOAD_EV_HUP,1},{1,NGX_FF_RELOAD_EV_ALL_READY,2},
    {1,NGX_FF_RELOAD_EV_READY_TIMEOUT,6},{1,NGX_FF_RELOAD_EV_GNEW_DIED,6},
    {2,NGX_FF_RELOAD_EV_HANDOVER_DONE,3},{2,NGX_FF_RELOAD_EV_ABORT,6},
    {3,NGX_FF_RELOAD_EV_DRAIN_DONE,4},{3,NGX_FF_RELOAD_EV_ABORT,6},
    {4,NGX_FF_RELOAD_EV_QUIT_GOLD,5},{4,NGX_FF_RELOAD_EV_ABORT,6},
    {5,NGX_FF_RELOAD_EV_GOLD_EXITED,0},{6,NGX_FF_RELOAD_EV_RESET,0}
};
static const int round_events[] = {
    NGX_FF_RELOAD_EV_HUP,NGX_FF_RELOAD_EV_ALL_READY,NGX_FF_RELOAD_EV_HANDOVER_DONE,
    NGX_FF_RELOAD_EV_DRAIN_DONE,NGX_FF_RELOAD_EV_QUIT_GOLD,NGX_FF_RELOAD_EV_GOLD_EXITED
};
static void round_trip(void)
{
    int state=0;
    const int next[]={1,2,3,4,5,0};
    for (unsigned i=0;i<6;i++) { state=example_reload_next(state,round_events[i]); CHECK(state==next[i]); }
}
static void transitions(void)
{
    round_trip();
    CHECK(example_reload_next(5,NGX_FF_RELOAD_EV_HUP)==NGX_FF_RELOAD_T_MAX);
    CHECK(example_reload_next(1,NGX_FF_RELOAD_EV_HUP)==NGX_FF_RELOAD_T_MAX);
    CHECK(example_reload_next(0,NGX_FF_RELOAD_EV_DRAIN_DONE)==NGX_FF_RELOAD_T_MAX);
    CHECK(example_reload_next(3,NGX_FF_RELOAD_EV_ALL_READY)==NGX_FF_RELOAD_T_MAX);
    CHECK(example_reload_next(0,NGX_FF_RELOAD_EV_GOLD_EXITED)==NGX_FF_RELOAD_T_MAX);
    CHECK(example_reload_next(1,NGX_FF_RELOAD_EV_GNEW_DIED)==6);
    CHECK(example_reload_next(1,NGX_FF_RELOAD_EV_READY_TIMEOUT)==6);
    CHECK(example_reload_next(6,NGX_FF_RELOAD_EV_RESET)==0);
    for (int state=0;state<NGX_FF_RELOAD_T_MAX;state++) CHECK(example_reload_state_name(state));
    CHECK(!strcmp(example_reload_state_name(0),"T0_IDLE"));
}
static void all_legal(void)
{
    for (unsigned i=0;i<sizeof(legal)/sizeof(legal[0]);i++)
        CHECK(example_reload_next(legal[i].state,legal[i].event)==legal[i].next);
    round_trip(); round_trip();
}
static void illegal(void)
{
    CHECK(NGX_FF_RELOAD_T_MAX==7 && NGX_FF_RELOAD_EV_MAX==11);
    for (int state=0;state<7;state++) for (int event=0;event<11;event++) {
        int expected=7;
        for (unsigned i=0;i<sizeof(legal)/sizeof(legal[0]);i++)
            if (legal[i].state==state && legal[i].event==event) expected=legal[i].next;
        CHECK(example_reload_next(state,event)==expected);
    }
    const int bad[]={7,-1,99};
    for (unsigned i=0;i<3;i++) for (int event=0;event<11;event++) CHECK(example_reload_next(bad[i],event)==7);
}
static void recovery(void)
{
    const struct transition errors[]={{1,NGX_FF_RELOAD_EV_READY_TIMEOUT,6},{1,NGX_FF_RELOAD_EV_GNEW_DIED,6},
        {2,NGX_FF_RELOAD_EV_ABORT,6},{3,NGX_FF_RELOAD_EV_ABORT,6},{4,NGX_FF_RELOAD_EV_ABORT,6}};
    for (unsigned i=0;i<5;i++) {
        int state=example_reload_next(errors[i].state,errors[i].event); CHECK(state==6);
        CHECK(example_reload_next(state,NGX_FF_RELOAD_EV_RESET)==0);
        CHECK(example_reload_next(state,NGX_FF_RELOAD_EV_HUP)==7);
        CHECK(example_reload_next(state,NGX_FF_RELOAD_EV_GOLD_EXITED)==7);
        round_trip();
    }
}
int main(int argc,char **argv)
{
    CHECK(argc==2);
    if (!strcmp(argv[1],"transitions")) transitions();
    else if (!strcmp(argv[1],"legal")) all_legal();
    else if (!strcmp(argv[1],"illegal")) illegal();
    else if (!strcmp(argv[1],"recovery")) recovery();
    else CHECK(0);
    printf("PASS: original caller reload FSM %s\n",argv[1]); return 0;
}
