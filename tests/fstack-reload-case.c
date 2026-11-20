#include <stdint.h>
#include <string.h>
#include "check.h"
#include "ff_config.h"
#include "ff_reload.h"

#define assert_int_equal(actual, expected) CHECK((actual) == (expected))
#include SOURCE_INCLUDE

int main(void)
{
    SOURCE_FUNCTION(NULL);
    CHECK(!ff_reload_state_attached());
    return 0;
}
