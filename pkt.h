#ifndef PKT_H_
#define PKT_H_
#include "peer_proto.h"
#include "util.h"

void pkt_ipv4_pack(struct _pkt_ipv4_host *ph, const struct ipv4_host *h);
void pkt_ipv4_unpack(const struct _pkt_ipv4_host *pip, struct ipv4_host *uip);


#endif
