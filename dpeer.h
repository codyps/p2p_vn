#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stdbool.h>
#include "routing.h"

typedef struct direct_peer {
	int con_fd;
	pthread_mutex_t wlock;

	pthread_t dp_th;

	ether_addr_t remote_mac;
	struct sockaddr_in addr;
	uint32_t rtt;


} direct_peer_t;

int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd);

#endif
