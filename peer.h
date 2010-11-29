#ifndef PEER_H_
#define PEER_H_ 1

struct peer_s {
	int con_fd;

	uint8_t mac[6];

	struct ipv4_host ex_host;
	struct ipv4_host in_host;

	bool in_th_down;
	pthread_mutex_t in_th_down_lock;

	bool out_th_down;
	pthread_mutex_t out_th_down_lock;

	pthread_t out_th;
	pthread_t in_th;
	pthread_t route_th;

	struct q in_to_route_q;
	struct q route_to_out_q;
};

#endif
