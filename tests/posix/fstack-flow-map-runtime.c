#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <ff_api.h>
#include <ff_config.h>
#include <ff_flow_map.h>
#include <ff_reload.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message) do { \
	if (!(condition)) { \
		fprintf(stderr, "C27 runtime flow map: %s\n", message); \
		return 1; \
	} \
} while (0)

static int same_object(const void *const *symbols, size_t count)
{
	Dl_info first = {0};
	if (!count || !dladdr(symbols[0], &first) || !first.dli_fname)
		return 0;
	char *real_first = realpath(first.dli_fname, NULL);
	if (!real_first) return 0;
	int same = 1;
	for (size_t index = 1; index < count; ++index) {
		Dl_info current = {0};
		if (!dladdr(symbols[index], &current) || !current.dli_fname) {
			same = 0;
			break;
		}
		char *real_current = realpath(current.dli_fname, NULL);
		if (!real_current || strcmp(real_first, real_current)) same = 0;
		free(real_current);
		if (!same) break;
	}
	free(real_first);
	return same;
}

int main(void)
{
	struct ff_reload_state state = {0};
	struct ff_flow_key key = {
		.af = FF_FLOW_MAP_V4,
		.src = {UINT32_C(0xc6336409)},
		.dst = {UINT32_C(0xc6336414)},
		.sport = UINT16_C(0x3412),
		.dport = UINT16_C(0x5000),
	};
	const void *runtime_symbols[] = {
		(const void *)ff_flow_map_open,
		(const void *)ff_flow_map_close,
		(const void *)ff_flow_map_lookup,
		(const void *)ff_flow_map_insert,
		(const void *)ff_flow_map_active,
		(const void *)ff_flow_map_admit,
		(const void *)ff_flow_map_revoke,
		(const void *)ff_reload_state_valid,
		(const void *)ff_reload_attach_state,
		(const void *)ff_reload_set_epoch,
		(const void *)ff_reload_set_gen,
		(const void *)&ff_global_cfg,
	};
	int created = 9;

	CHECK(same_object(runtime_symbols,
		sizeof(runtime_symbols) / sizeof(runtime_symbols[0])),
		"map, reload context, and config must resolve from one runtime DSO");

	ff_global_cfg.dpdk.graceful_reload = 0;
	ff_reload_attach_state(NULL);
	ff_flow_map_open();
	CHECK(!ff_flow_map_active(), "detached/default runtime became active");
	CHECK(ff_flow_map_admit(&key, &created) == 1 && created == 0,
		"inactive admission must preserve original allow-without-record behavior");
	CHECK(ff_flow_map_insert(&key) < 0,
		"inactive direct insert must preserve original rejection behavior");
	CHECK(ff_flow_map_lookup(&key) == 0,
		"inactive admission unexpectedly recorded a key");
	ff_flow_map_close();

	state.magic = FF_RELOAD_STATE_MAGIC;
	state.version = FF_RELOAD_STATE_VERSION;
	state.len = sizeof(state);
	state.epoch = 1;
	state.active_gen = 0;
	state.target_gen = 0;
	state.kni_owner_gen = 0;
	state.rx_owner_gen = 0;
	CHECK(ff_reload_state_valid(&state, sizeof(state)),
		"caller-built original reload block did not validate");
	ff_global_cfg.dpdk.graceful_reload = 1;
	ff_reload_set_epoch(1);
	ff_reload_set_gen(0);
	ff_reload_attach_state(&state);
	CHECK(ff_reload_state_attached(), "original attach API did not attach state");
	ff_flow_map_cap_set(8);
	ff_flow_map_open();
	CHECK(ff_flow_map_active(), "valid attached window did not activate map");
	CHECK(ff_flow_map_admit(&key, &created) == 1 && created == 1,
		"first admission was not recorded");
	CHECK(ff_flow_map_lookup(&key) == 1, "inserted key was not found");
	created = 9;
	CHECK(ff_flow_map_admit(&key, &created) == 1 && created == 0,
		"duplicate admission changed the original map semantics");
	CHECK(ff_flow_map_revoke(&key) == 1 && ff_flow_map_lookup(&key) == 0,
		"revoke did not remove the exact key");
	CHECK(ff_flow_map_insert(&key) == 0,
		"second active insertion failed before close test");
	ff_flow_map_close();
	CHECK(!ff_flow_map_active() && ff_flow_map_lookup(&key) == 0,
		"close left the map active or visible");
	ff_flow_map_open();
	CHECK(ff_flow_map_active() && ff_flow_map_lookup(&key) == 0,
		"reopened map did not start empty");
	ff_flow_map_close();
	ff_reload_attach_state(NULL);
	ff_reload_set_epoch(0);
	ff_reload_set_gen(0);
	ff_global_cfg.dpdk.graceful_reload = 0;
	puts("PASS: original map lifecycle and reload/config state share installed runtime DSO");
	return 0;
}
