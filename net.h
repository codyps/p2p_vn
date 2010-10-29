#ifndef NET_H_
#define NET_H_ 1

struct net_data {
	char *ifname;
	int net_sock;
	int ifindex;
};

#endif
