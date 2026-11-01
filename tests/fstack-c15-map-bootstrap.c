#define _GNU_SOURCE
#include "check.h"
#include <ker/reload.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include "ff_config.h"
#include "ff_flow_map.h"

/* Compile the actual Ker reload adapter and unchanged F-Stack map in this
 * fixture. No example policy macro substitutes either upstream gate. */
#include "../src/compat/reload.c"
#include "../third_party/fstack-flow-map/ff_flow_map.c"

static struct ff_flow_key test_key(void)
{
	struct ff_flow_key key = {0};
	key.af = FF_FLOW_MAP_V4;
	key.src[0] = htonl(0xc0000201);
	key.dst[0] = htonl(0xc0000202);
	key.sport = htons(41001);
	key.dport = htons(8080);
	return key;
}

int main(void)
{
	size_t size = ker_reload_state_size();
	void *state = calloc(1, size);
	int created = 0;
	uint64_t inserted = 0, duplicates = 0;
	struct ff_flow_key key = test_key();

	CHECK(state != NULL);
	CHECK(!ker_reload_state_init(state, size, 0));
	CHECK(!ker_reload_bind_state(state, size, 1, 0));
	CHECK(ff_global_cfg.dpdk.graceful_reload == 1);
	CHECK(ff_reload_state_attached());
	ff_flow_map_open();
	CHECK(ff_flow_map_active());
	CHECK(ff_flow_map_admit(&key, &created) == 1 && created == 1);
	CHECK(ff_flow_map_lookup(&key) == 1);
	created = 1;
	CHECK(ff_flow_map_admit(&key, &created) == 1 && created == 0);
	ff_flow_map_stats(&inserted, &duplicates, NULL);
	CHECK(inserted == 1 && duplicates == 1);
	CHECK(ff_flow_map_revoke(&key) == 1 && ff_flow_map_lookup(&key) == 0);
	ff_flow_map_close();
	CHECK(!ff_flow_map_active());
	ker_reload_unbind_state();
	CHECK(!ff_reload_state_attached());
	CHECK(ff_global_cfg.dpdk.graceful_reload == 0);
	free(state);
	puts("PASS: actual reload attachment and original active flow-map admission/duplicate/revoke path");
	return 0;
}
