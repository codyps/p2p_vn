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

	routing_t *rd;
	dpg_t *dpg;
} direct_peer_t;

typedef uint32_t __be32;
typedef uint16_t __be16;

int dp_init_initial(direct_peer_t *dp, routing_t *rd,  dpg_t *dpg,
		char *host, char *port);

int dp_init_linkstate(direct_peer_t *dp, routing_t *rd, dpg_t *dpg,
		ether_addr_t mac, __be32 inet_addr, __be16 inet_port);

int dp_init_incoming(direct_peer_t *dp, routing_t *rd, dpg_t *dpg,
		int fd);

#endif
