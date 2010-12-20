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

static int host_cmp(const void *kp1_v, const void *kp2_v)
{
	const _rt_host *const *eth1 = kp1_v;
	const _rt_host *const *eth2 = kp2_v;

	const ether_addr_t *a1 = *eth1;
	const ether_addr_t *a2 = *eth2;
	return memcmp(a1, a2, ETH_ALEN);
}

static int link_cmp(const void *kp1_v, const void *kp2_v)
{
	return;
}

struct _rt_host* rt_host_init(ether_addr_t *mac)
{
	struct _rt_host *hst = malloc(INIT_HOSTS_MEM * sizeof(*hst));
	hst->ts_ms = 0;
	hst->addr = mac;
	hst->out_links = malloc(INIT_LINKS_MEM * sizeof(*hst->out_links));
	hst->l_ct = 0;
	hst->l_mem = INIT_LINKS_MEM;
	
	return hst;
}

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
	free(rd->hosts);
	pthread_rwlock_destroy(&rd->lock);
}

/*general add to routing list */
int gen_host_add(routing_t *rd, ether_addr_t *mac)
{
	struct _rt_host **dup = bsearch(&mac, rd->hosts, rd->h_ct, sizeof(*rd->hosts),
			host_cmp);
			
	/* dpeer already exsists. */
	if(dup) {
		pthread_rwlock_unlock(&rd->lock);
		return 1;
	}
	
	if (rd->h_ct + 1 > rd->h_mem) {
		/* we need more memory to fit the pointer */
		size_t n_h_mem = rd->h_mem * 2;
		
		struct _rt_host **rd_m = realloc(rd->hosts, n_h_mem * sizeof(*rd->hosts));
		if(!rd_m) {
			pthread_rwlock_unlock(&rd->lock);
			return -2;
		}
		
		rd->h_mem = n_h_mem;
		rd->hosts = rd_m;
	}
	
	rd->hosts[rd->h_ct] = rt_host_init(mac);
	rd->h_ct++;
	
	/* resort the list */
	qsort(rd->hosts, rd->h_ct, sizeof(*rd->hosts), host_cmp);
	
	return 0;
}
/*
 * on failure, returns < 0.
 * if a duplicate exsists, returns 1.
 * otherwise, returns 0.
 */
int rt_lhost_add(routing_t *rd, ether_addr_t mac)
{
	pthread_rwlock_wrlock(&rd->lock);
	
	int p = gen_host_add(rd, &mac);
	
	pthread_rwlock_unlock(&rd->lock);

	return p;
}

int rt_dhost_add_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t *dst_mac, uint32_t rtt_us)
{
	pthread_rwlock_wrlock(&rd->lock);
	
	struct _rt_host **hst = bsearch(&src_mac, rd->hosts, rd->h_ct, 
		sizeof(*rd->hosts), host_cmp);
			
	if(hst) {
		struct _rt_link *link = bsearch(&dst_mac, hst->out_links, hst->l_ct,
			 sizeof(hst->out_links), host_cmp);
		if(link) {
			hst->is_dpeer = 1;
			link->rtt_us = rtt_us;
		//	link->ts_ms = 
		} else {
		gen_host_add(rd, dst_mac);
		
		}
	
	}
	
	int t = rt_lhost_add(rd, dst_mac);
	if(t == 1) { /*compare func broke*/return 1; }
	
	pthread_rwlock_unlock(&rd->lock);

	return -1;
}

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

