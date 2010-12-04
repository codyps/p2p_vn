#ifndef LNET_H_
#define LNET_H_ 1

typedef struct local_netif {
	int fd;
	pthread_mutex_t wlock;
	ether_addr_t mac;
} ln_t;

static int lnd_send(struct local_netif *nd,
		void *packet, size_t size);

#endif
