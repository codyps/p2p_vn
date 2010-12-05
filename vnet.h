#ifndef LNET_H_
#define LNET_H_ 1


#define VNET_MAC(vnet) ((vnet)->mac)

typedef struct virt_netif {
	int fd;
	char *ifname;
	pthread_mutex_t wlock;
	ether_addr_t mac;
} vnet_t;

int vnet_init(vnet_t *vn, char *ifname);
int vnet_send(vnet_t *vn, void *packet, size_t size);
int vnet_recv(vnet_t *nd, void *buf, size_t *nbyte);

#endif
