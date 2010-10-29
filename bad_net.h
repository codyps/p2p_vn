#ifndef BAD_NET_H_
#define BAD_NET_H_ 1

#include "net.h"
int bad_net_init(struct net_data *nd, char *ifname);
int bad_net_recv_packet(struct net_data *nd, void *buf, size_t *nbyte);
int bad_net_send_packet(struct net_data *nd,
		void *packet, size_t size);
#endif
