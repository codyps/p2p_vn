#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stdbool.h>
#include "routing.h"

#define DPEER_MAC(dp) ((dp)->remote_mac)

typedef struct direct_peer {
	int con_fd;
	pthread_mutex_t wlock;

	pthread_t dp_th;

	ether_addr_t remote_mac;
	struct sockaddr_in addr;
	uint32_t rtt;

	dpg_t *dpg;
	routing_t *rd;
	vnet_t *vnet;
} direct_peer_t;

typedef uint32_t __be32;
typedef uint16_t __be16;


#define dp_from_eth(eth) container_of(eth, struct direct_peer, remote_mac);

/* sends a data packet.
 * for use by the vnet thread
 */
int dp_send_data(direct_peer_t *dp, void *data, size_t len);

int dp_init_initial(direct_peer_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		char *host, char *port);

int dp_init_linkstate(direct_peer_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		ether_addr_t mac, __be32 inet_addr, __be16 inet_port);

int dp_init_incoming(direct_peer_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		int fd, struct sockaddr *addr);

#endif
