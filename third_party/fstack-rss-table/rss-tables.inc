struct ff_rss_tbl_dip_type {
    uint32_t daddr;
    uint16_t first; /* The start port in portrange */
    uint16_t last; /* The end port in portrange */
    uint16_t first_idx; /* The idx of the start port in portrange */
    uint16_t last_idx; /* The idx of the end port in portrange */
    uint16_t num;
    uint16_t dport[FF_RSS_TBL_MAX_DPORT + 1]; /* [0] used as the idx of last seleted port */
} __rte_cache_aligned;

struct ff_rss_tbl_type {
    //enum ff_rss_tbl_init_type init;
    uint32_t saddr;
    uint16_t sport;
    uint16_t num;
    struct ff_rss_tbl_dip_type dip_tbl[FF_RSS_TBL_MAX_DADDR];
} __rte_cache_aligned;
static struct ff_rss_tbl_type ff_rss_tbl[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];

/* IPv6 (scheme A): v6-dedicated table/functions, parallel to v4.
 * 16-byte addresses; everything else mirrors the v4 layout. v4 path untouched. */
struct ff_rss_tbl6_dip_type {
    uint8_t daddr6[16];
    uint16_t first;
    uint16_t last;
    uint16_t first_idx;
    uint16_t last_idx;
    uint16_t num;
    uint16_t dport[FF_RSS_TBL_MAX_DPORT + 1];
} __rte_cache_aligned;

struct ff_rss_tbl6_type {
    uint8_t saddr6[16];
    uint16_t sport;
    uint16_t num;
    struct ff_rss_tbl6_dip_type dip_tbl[FF_RSS_TBL_MAX_DADDR];
} __rte_cache_aligned;
static struct ff_rss_tbl6_type ff_rss_tbl6[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];
