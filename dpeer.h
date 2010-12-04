#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stdbool.h>
#include "routing.h"

typedef struct dpeer_s {
	int con_fd;

	ether_addr_t remote_mac;

	bool in_th_down;
	pthread_mutex_t in_th_down_lock;

	bool out_th_down;
	pthread_mutex_t out_th_down_lock;

	pthread_t out_th;
	pthread_t in_th;
	pthread_t route_th;

	struct q in_to_route_q;
	struct q route_to_out_q;
} direct_peer_t;

int dp_init(direct_peer_t *dp, ether_addr_t mac, int confd);

#endif
