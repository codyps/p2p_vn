#ifndef ROUTING_H_
#define ROUTING_H_

#include <netinet/in.h> /* struct sockaddr_storage */
#include <netinet/if_ether.h> /* ETHER_ADDR_LEN */

#include <stdint.h>
#include <pthread.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

typedef uint8_t ether_addr_t[ETH_ALEN];

struct rt_hosts {
	ether_addr_t addr;
	struct rt_hosts *next;
};

typedef struct routing_s {
	size_t host_ct;
	size_t host_mem;
	struct rt_host **hosts;
	pthread_mutex_t lock;
} routing_t;

#define ROUTING_INITIALIZER { \
	.host_ct = 0, .host_mem = 0, .hosts = NULL, \
	.lock = PTHREAD_MUTEX_INITIALIZER }

/* all functions: on error, return negative */

/* Initializes routing data structure
 * thread safe: no */
int rt_init(routing_t *rd);

/* Ditch all reasources associated with `rd'.
 * If called on a non-empty routing_t, result is undefined
 * thread safe: no */
void rt_destroy(routing_t *rd);

/* adds a host with no links. not the best choice. */
int rt_add_host(routing_t *rd, ether_addr_t mac);

/* add a link. Will create hosts if they do not exsist.
 * if link exsists, will update rtt */
int rt_add_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t dst_mac, uint64_t rtt);

/* also purges all links to/from this node */
int rt_remove_host(routing_t *rd, ether_addr_t mac);

/* this allows us to have the packet be sent to multiple places,
 * allowing multicast to function properly.
 * *res is set to a list of rt_hosts. */
int rt_hosts_to_host(routing_t *rd,
		ether_addr_t src_mac, ether_addr_t dst_mac,
		struct rt_hosts **res);

/* frees the list of rt_hosts */
void rt_hosts_free(routing_t *rd, struct rt_hosts *hosts);

#endif
