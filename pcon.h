
#ifndef _PEER_CON_H
#define _PEER_CON_H

#include <sys/time.h>
#include "routing.h"

struct ipv4_host {
	ether_addr_t mac;
	struct sockaddr_in in;
	struct timeval attempt_ts;
};

typedef struct peer_cons {
	struct ipv4_host *hosts;
	size_t h_mem;
	size_t h_ct;
} pcon_t;

/* on error, returns < 0.
 * if connection should occour, returns 0.
 * if connection should not be attempted returns 1.
 */
int pcon_should_connect(pcon_t *pc, ether_addr_t mac, struct sockaddr_in in);

int pcon_init(pcon_t *pc);
void pcon_destroy(pcon_t *pc);

#endif
