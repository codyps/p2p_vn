#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stdbool.h>
#include "routing.h"

typedef struct direct_peer {
	int con_fd;

	ether_addr_t remote_mac;

	/* Signalling on "down" status */
	bool dflag_in;
	pthread_mutex_t dlock_in;

	bool dflag_out;
	pthread_mutex_t dlock_out;


	pthread_t th_route;
	pthread_t th_in;
	pthread_t th_out;

	struct q in_to_route;
	struct q route_to_out;
} direct_peer_t;

int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd);

#endif
