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

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

typedef struct ether_addr_s {
	uint8_t addr[ETH_ALEN];
} ether_addr_t;

struct rt_hosts {
	ether_addr_t *addr;
	struct rt_hosts *next;
};

struct _rt_host {
	ether_addr_t *addr;
	bool is_dpeer;

	/* the remote timestamp in microseconds */
	uint64_t ts_us;

	/* * to [] of * */
	struct _rt_link *out_links;
	struct _rt_link *in_links;

	size_t l_ct;
	size_t l_mem;
};

struct _rt_link {
	struct _rt_host *dst;
	uint32_t rtt;
};

typedef struct routing_s {
	/* * to [] of * */
	struct _rt_host **hosts;
	size_t h_ct;
	size_t h_mem;

	pthread_rwlock_t lock;
} routing_t;

#define ROUTING_INITIALIZER { \
	.host_ct = 0, .host_mem = 0, .hosts = NULL, \
	.lock = PTHREAD_MUTEX_INITIALIZER }

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
int rt_dhost_add(routing_t *rd, ether_addr_t *mac);

/* add a link to a direct peer. Intended for use when a new connection is
 * established or RTT is updated.
 *
 * Will create dst_node if it does not exsist.
 * if link exsists, rtt is updated */
int rt_dhost_add_link(routing_t *rd, ether_addr_t *src_mac,
		ether_addr_t *dst_mac, uint32_t rtt);

/**
 * rt_ihost_set_link - sets the links for a given node. Routing copies
 *	specified data, it may be freed following this call's completion.
 *
 *      if link exsists, rtt is updated.
 *
 * @rd        the routing data
 * @src_mac   mac address of the host which sent us this information. also is
 *            the host where the edges originate.
 * @rem_ts_us the remote timestamp in microseconds attached to this set of
 *            links
 * @dst_macs  an array of pointers to mac addresses, paired with rtts.
 * @rtts      an array of pointers to round trip times. Each is the wieght
 *            for a unique edge.
 * @len       the number of edges this call intends to set.
 *            essentially, length(dst_macs) = length(rtts) = len.
 *
 */
int rt_ihost_set_link(routing_t *rd, ether_addr_t *src_mac, uint64_t rem_ts_us,
		ether_addr_t **dst_macs, uint32_t **rtts, size_t len);

/* also purges all links to/from this node */
int rt_remove_host(routing_t *rd, ether_addr_t *mac);

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
		ether_addr_t *src_mac, ether_addr_t *cur_mac,
		ether_addr_t *dst_mac, struct rt_hosts **res);

/**
 * rt_hosts_free - frees the list of rt_hosts.
 *
 * @rd    the routing data the hosts were obtained from
 * @hosts the first host of a linked list of hosts returned by
 *        rt_dhosts_to_host.
 */
void rt_hosts_free(routing_t *rd, struct rt_hosts *hosts);

#endif
