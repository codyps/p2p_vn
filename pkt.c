#include "peer_proto.h"
#include "util.h"
#include <string.h>
#include <arpa/inet.h>

void pkt_ipv4_unpack(const struct _pkt_ipv4_host *pip, struct ipv4_host *ip)
{
	ip->in.sin_family = AF_INET;
	memcpy(ip->mac.addr, pip->mac, ETH_ALEN);
	ip->in.sin_addr.s_addr = pip->ip;
	ip->in.sin_port = pip->port;
}

void pkt_ipv4_pack(struct _pkt_ipv4_host *ph, const struct ipv4_host *h)
{
	ph->ip = htonl(h->in.sin_addr.s_addr);
	ph->port = htons(h->in.sin_port);
	memcpy(ph->mac, h->mac.addr, ETH_ALEN);
}
