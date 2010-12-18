#include <stdlib.h>

#include <pthread.h>
#include <stdint.h>

#include "routing.h"

#define INIT_HOSTS_MEM 8
#define INIT_LINKS_MEM 2

#if 0
struct _rt_host {
	ether_addr_t *addr;
	bool alloc_addr;

	/* * to [] of * */
	struct _rt_link *links;
	size_t l_ct;
	size_t l_mem;
};

struct _rt_link {
	struct _rt_host *dst;
	uint32_t rtt;
};

typedef struct routing_s {
	/* * to [] of * */
	struct _rt_host **hosts;
	size_t h_ct;
	size_t h_mem;

	pthread_rwlock_t lock;
} routing_t;
#endif


int rt_init(routing_t *rd)
{
	int ret = pthread_rwlock_init(&rd->lock, NULL);
	if (ret < 0)
		return ret;

	rd->hosts = malloc(sizeof(*rd->hosts) * INIT_HOSTS_MEM);
	if (!rd->hosts)
		return -1;

	rd->h_ct = 0;
	rd->h_mem = INIT_HOSTS_MEM;
	return 0;
}

void rt_destroy(routing_t *rd)
{
	pthread_rwlock_destroy(&rd->lock);
}

int rt_dhost_add(routing_t *rd, ether_addr_t *mac)
{
	pthread_rwlock_wrlock(&rd->lock);
	pthread_rwlock_unlock(&rd->lock);

	return -1;
}

int rt_dhost_add_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t *dst_mac, uint32_t rtt_us)
{
	pthread_rwlock_wrlock(&rd->lock);
	pthread_rwlock_unlock(&rd->lock);

	return -1;
}

#if 0
int rt_ihost_set_link(routing_t *rd, ether_addr_t *src_mac,
		struct _pkt_neighbor *ns, size_t n_ct)
{
	pthread_rwlock_wrlock(&rd->lock);
	pthread_rwlock_unlock(&rd->lock);

	return -1;
}
#endif

int rt_update_edges(routing_t *rd, struct _pkt_edge *edges, size_t e_ct)
{
	pthread_rwlock_wrlock(&rd->lock);
	pthread_rwlock_unlock(&rd->lock);
	return -1;
}

int rt_remove_host(routing_t *rd, ether_addr_t *mac)
{
	pthread_rwlock_wrlock(&rd->lock);
	pthread_rwlock_unlock(&rd->lock);
	return -1;
}

/* locking paired with rt_hosts_free due to dual owner of dpeer's mac */
int rt_dhosts_to_host(routing_t *rd,
		ether_addr_t *src_mac, ether_addr_t *cur_mac,
		ether_addr_t *dst_mac, struct rt_hosts **res)
{
	pthread_rwlock_rdlock(&rd->lock);

	return -1;
}

void rt_hosts_free(routing_t *rd, struct rt_hosts *hosts)
{
	pthread_rwlock_unlock(&rd->lock);
	while(hosts != NULL) {
		struct rt_hosts *next = hosts->next;
		free(hosts);
		hosts = next;
	}
}

