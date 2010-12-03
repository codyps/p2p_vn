#ifndef ROUTING_H_
#define ROUTING_H_

#include <netinet/in.h> /* struct sockaddr_storage */
#include <net/ethernet.h> /* ETHER_ADDR_LEN */

#include <stdint.h>

struct host {
	/* sa.ss_family == (AF_INET || AF_INET6)
	 * cast to either (struct) `sockaddr_in` or `sockaddr_in`
	 *  in  -> .sin_port, .sin_addr
	 *  in6 -> .sin6_port, .sin6_addr
	 * Other fields unneeded.
	 */
	struct sockaddr_storage sa;
	uint8_t mac_addr[ETHER_ADDR_LEN];

	uint64_t rtt;
};

typedef struct routing_s {
	size_t host_ct;
	struct host **hosts;
} routing_t;

/* Initializes routing data structure
 * thread safe: no */
int rt_init(routing_t *rd);

/* Do not free host while rt is using it.
 * MM responsibility falls to caller */
int rt_add_host(routing_t *rd, struct host *host);

/* Must have a pointer to host to remove it. May change at some point */
int rt_remove_host(routing_t *rd, struct host *host);

/* Indicate to rt that the host's rtt was updated */
int rt_updated_rtt(routing_t *rd, struct host *host);

/* Ditch all reasources associated with `rd'.
 * If called on a non-empty routing_t, result is undefined */
void rt_destroy(routing_t *rd);

#endif
