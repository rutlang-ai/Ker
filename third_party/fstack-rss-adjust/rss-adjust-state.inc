#define FF_RSS_THASH_V4_TUPLE_LEN   12
#define FF_RSS_THASH_V4_SPORT_OFF   80
#define FF_RSS_THASH_SPORT_HELPER_LEN   16
#define FF_RSS_THASH_ADJUST_ATTEMPTS    16
#define FF_RSS_THASH_V6_TUPLE_LEN   36
#define FF_RSS_THASH_V6_SPORT_OFF   272
static struct rte_thash_ctx *rss_thash_ctx[RTE_MAX_ETHPORTS];
static struct rte_thash_subtuple_helper *rss_thash_sport_h[RTE_MAX_ETHPORTS];
static int rss_thash_ready[RTE_MAX_ETHPORTS];
static struct rte_thash_ctx *rss_thash6_ctx[RTE_MAX_ETHPORTS];
static struct rte_thash_subtuple_helper *rss_thash6_sport_h[RTE_MAX_ETHPORTS];
static int rss_thash6_ready[RTE_MAX_ETHPORTS];
static int ff_rss_key_built;
