#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stdbool.h>
#include "routing.h"

struct mac_addr_lst {
	
	
}


typedef struct direct_peer {
	int con_fd;

	ether_addr_t remote_mac;

	
	pthread_t dp_th;


} direct_peer_t;

int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd);

#endif
