/* Private fixture: original test-only budget knob, real EAL role/mapping/fatal.
 * No role, timestamp, CAS, mapping or fatal interception in this executable. */
#include "../src/compat/reload.c"
#define KER_RELOAD_SLOT_TESTING
#define KER_RELOAD_SLOT_OBSERVATIONS
#include "fstack-reload-directory-multiprocess.c"
