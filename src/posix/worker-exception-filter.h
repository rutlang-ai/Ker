#ifndef KER_WORKER_EXCEPTION_FILTER_H
#define KER_WORKER_EXCEPTION_FILTER_H
#include <stdbool.h>
#include <stdint.h>
#include <rte_mbuf.h>
enum ker_exception_class { KER_EXCEPTION_UNKNOWN, KER_EXCEPTION_SERVICE,
    KER_EXCEPTION_OSPF, KER_EXCEPTION_NDP, KER_EXCEPTION_FRAGMENT };
struct ker_exception_filter { unsigned char tcp[8192], udp[8192]; };
/* Strict decimal comma lists and inclusive ranges, 0..65535; NULL/empty means
 * no selected ports. Failure leaves the destination untouched. */
int ker_exception_filter_init(struct ker_exception_filter *, const char *tcp, const char *udp);
/* NULL port sets disable service matching; control classification remains. */
enum ker_exception_class ker_exception_classify(const struct ker_exception_filter *, const struct rte_mbuf *);
bool ker_exception_arp(const struct rte_mbuf *);
#endif
