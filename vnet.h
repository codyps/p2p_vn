#ifndef LNET_H_
#define LNET_H_ 1

typedef struct virtual_net_interface vnet_t;

#include <pthread.h>
#include "routing.h"
#include "dpg.h"

struct virtual_net_interface {
	int fd;
	char *ifname;
	pthread_mutex_t wlock;
	ether_addr_t mac;
};

/* initializes the tap device named `ifname' */
int vnet_init(vnet_t *vn, char *ifname);

/* send packet to the tap device */
int vnet_send(vnet_t *vn, void *packet, size_t size);

/* read a packet from the tap device (vnet thread only) */
int vnet_recv(vnet_t *nd, void *buf, size_t *nbyte);

/* return the mtu of the vnet device */
int vnet_get_mtu(vnet_t *vn);

/* return the current vnet address */
ether_addr_t vnet_get_mac(vnet_t *vn);

/* spawn the vnet listener thread */
int vnet_spawn_listener(vnet_t *vnet, routing_t *rd, dpg_t *dpg);
#endif
