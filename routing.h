#ifndef ROUTING_H_
#define ROUTING_H_ 1

/**
 * Manages a set of hosts (nodes) distinguised by their ether_addr_t
 * and paths (edges) between these hosts with an attached RTT (cost)
 *
 * Expected to be able to indicate where data from a given host (in all the
 * uses within this project, the localhost) to any other connected host.
 */

#include <netinet/in.h> /* struct sockaddr_storage */
#include <netinet/if_ether.h> /* ETHER_ADDR_LEN */

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "util.h"
#include "peer_proto.h"


struct rt_hosts {
	struct ipv4_host *addr;
	struct rt_hosts *next;
};

struct _rt_link {
	struct _rt_host *dst;
	uint32_t rtt_us;
	uint64_t ts_ms;
};

enum host_type {
	HT_LOCAL,
	HT_DIRECT,
	HT_NORMAL
};

struct _rt_host {
	struct ipv4_host *host;
	enum host_type type;

	/* * to [] of * */
	struct _rt_link *links;

	uint64_t l_max_ts_ms;
	size_t l_ct;
	size_t l_mem;
};

typedef struct routing_s {

	/* our knowledge of the network */
	struct _rt_host **hosts;
	size_t h_ct;
	size_t h_mem;

	/* data generated from the above */
	size_t m_ct;
	uint32_t **path;
	size_t **next;

	struct _pkt_edge *edges;
	size_t e_ct;
	size_t e_mem;

	pthread_rwlock_t lock;
} routing_t;

#define ROUTING_INITIALIZER { \
	.host_ct = 0, .host_mem = 0, .hosts = NULL, \
	.lock = PTHREAD_MUTEX_INITIALIZER }


/* god damn it */
void pkt_ipv4_pack(struct _pkt_ipv4_host *ph, struct ipv4_host *h);

/* all functions: on error, return negative */

/**
 * rt_init - Initializes routing data structure. Obviously not thread safe.
 *
 * @rd    the unititialized routing data to be initialized.
 */
int rt_init(routing_t *rd);

/* Ditch all reasources associated with `rd'.
 * If called on a non-empty routing_t, result is undefined
 * thread safe: no */
void rt_destroy(routing_t *rd);

/* adds a host with no links.
 * Intended for use in adding the 'root' direct peer (us) */
int rt_lhost_add(routing_t *rd, struct ipv4_host *host);

/* rt_dhost_add_link - add a link from src_mac to a direct peer indicated
 *                     by dst_mac. Intended for use in maintaining an creating
 *                     direct peer links.
 *
 *                     If src_mac does not refer to a valid host, the function
 *                     returns -1.
 *
 *                     If dst_mac does not refer to a valid host, a new dhost
 *                     is created.
 *
 *                     If dst_mac does refer to a valid host, but not a direct
 *                     host, the host is changed to a direct host.
 *
 *                     In all cases, rtt is updated.
 */
int rt_dhost_add_link(routing_t *rd, ether_addr_t src_mac,
		struct ipv4_host *dst_ip_host, uint32_t rtt_us);

/* Uses the edge data recived from a neighbor to update it's internal
 * understanding of the network. algorithm
 */
int rt_update_edges(routing_t *rd, struct _pkt_edge *edges, size_t e_ct);

/* also purges all links to/from this node */
int rt_remove_dhost(routing_t *rd, ether_addr_t lmac, ether_addr_t *dmac);

/**
 * rt_dhosts_to_host - Gives the caller every host they should forward the
 *                     packet described by the tuple {src_mac,dst_mac}.
 *
 * @rd      the routing data to retrieve info from.
 * @src_mac original source of the packet
 * @cur_mac current host the packet is on
 * @dst_mac the final destination (multicast/broadcast recognized)
 * @res     set to a linked list of rt_hosts which one should traverse and
 *          then call rt_hosts_free on (a lock is held between the call to
 *          this function and rt_hosts_free). This also means that one must
 *          not attempt to write to the routing data while they have a
 *          rt_hosts ll 'checked out', as the result will be deadlock.
 */
int rt_dhosts_to_host(routing_t *rd,
		ether_addr_t src_mac, ether_addr_t cur_mac,
		ether_addr_t dst_mac, struct rt_hosts **res);

/**
 * rt_hosts_free - frees the list of rt_hosts.
 *
 * @rd    the routing data the hosts were obtained from
 * @hosts the first host of a linked list of hosts returned by
 *        rt_dhosts_to_host.
 */
void rt_hosts_free(routing_t *rd, struct rt_hosts *hosts);

/**
 * rt_get_edges - gives the packed representation of the graph to the
 *                caller.
 * @rd            routing data from with the info is extracted
 * @edges         is set to the edges on success.
 * @e_ct          the count of edges (on success).
 *
 * return         negative on error. otherwise zero.
 */
int rt_get_edges(routing_t *rd, struct _pkt_edge **edges, size_t *e_ct);

/**
 * rt_edges_free - informs routing that we no longer require the edges it
 *		   gave us
 * @rd		routing data
 * @edges	edges returned by rt_get_edges.
 * @e_ct	number of edges
 */
void rt_edges_free(routing_t *rd, struct _pkt_edge *edges, size_t e_ct);

#endif
