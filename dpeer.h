#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stdbool.h>
#include "routing.h"

struct dpeer_lst {
	
}

typedef struct direct_peer {
	int con_fd;
	ether_addr_t remote_mac;
	pthread_mutex_t lock_wr;
	pthread_t dp_th;

	uint32_t rtt;
	struct sockaddr_in addr;
} direct_peer_t;

int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd);

#endif
