
#ifndef _PEER_CON_H
#define _PEER_CON_H

#include <sys/time.h>

typedef struct peer_cons pcon_t;

#include "routing.h"
#include "dpg.h"
#include "vnet.h"
#include "util.h"

struct ip_attempt {
	struct timeval attempt_ts;
	struct ipv4_host host;
};

struct peer_cons {
	struct ip_attempt *hosts;
	size_t h_mem;
	size_t h_ct;

	pthread_mutex_t lock;
};

/* on error, returns < 0.
 * if connection should occour, returns 0.
 * if connection should not be attempted returns 1.
 */
int pcon_connect(pcon_t *pc, dpg_t *dpg, routing_t *rd, vnet_t *vnet,
	       	struct ipv4_host *attempt_host);

int pcon_init(pcon_t *pc);
void pcon_destroy(pcon_t *pc);

#endif
