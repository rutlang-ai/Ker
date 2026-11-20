#include "check.h"
#include "ngx_ff_reload_fsm.h"
#include <string.h>

#define assert_int_equal(left, right) CHECK((left) == (right))
#define assert_non_null(value) CHECK((value) != NULL)
#define assert_string_equal(left, right) CHECK(!strcmp((left), (right)))
#include "fstack-reload-fsm-source.inc"

int main(int argc, char **argv)
{
    const struct {
        const char *name;
        void (*run)(void **);
    } cases[] = {
        {"transitions", test_ut_nr_10_reload_fsm_transitions},
        {"legal", test_ut_nr_10_all_legal_transitions},
        {"illegal", test_ut_nr_10_illegal_combinations_exhaustive},
        {"recovery", test_ut_nr_10_error_recovery_and_abort},
    };

    CHECK(argc == 2);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (!strcmp(argv[1], cases[i].name)) {
            cases[i].run(NULL);
            return 0;
        }
    }
    fprintf(stderr, "Unrecognized reload FSM case: %s\n", argv[1]);
    return 1;
}
