#include <stdlib.h>

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "routing.h"
#include "util.h"

#define RT_HOST_INIT 8
#define RT_LINK_INIT 8
#define RT_HOST_MULT 2
#define RT_LINK_MULT 2


/* host_cmp - compare (struct _rt_host **) */
static int host_cmp_addr(const void *kp1_v, const void *kp2_v)
{
	struct _rt_host const *const *h1 = kp1_v;
	struct _rt_host const *const *h2 = kp2_v;

	const ether_addr_t *a1 = (*h1)->addr;
	const ether_addr_t *a2 = (*h2)->addr;
	return memcmp(a1, a2, ETH_ALEN);
}

/* link_cmp - compare (struct _rt_link *) */
static int link_cmp_addr(const void *kp1_v, const void *kp2_v)
{
	struct _rt_link const *l1 = kp1_v;
	struct _rt_link const *l2 = kp2_v;

	const ether_addr_t *a1 = l1->dst->addr;
	const ether_addr_t *a2 = l2->dst->addr;
	return memcmp(a1, a2, ETH_ALEN);
}


static struct _rt_host **find_host_by_addr(
		struct _rt_host **hosts,
		size_t host_ct,
		ether_addr_t mac)
{
	struct _rt_host h = { .addr = &mac };
	struct _rt_host *key = &h;

	struct _rt_host **host = bsearch(&key, hosts, host_ct,
		sizeof(*hosts), host_cmp_addr);

	return host;
}

static struct _rt_link *find_link_by_addr(
		struct _rt_link *links,
		size_t link_ct,
		ether_addr_t dst_mac)
{
	struct _rt_host h = { .addr = &dst_mac };
	struct _rt_link l = { .dst = &h };

	struct _rt_link *nl = bsearch(&l, links, link_ct,
		sizeof(*links), link_cmp_addr);

	return nl;
}

/* updates the internal tracking of paths */
static int compute_paths(routing_t *rd)
{
	uint32_t **path;
	size_t **next;

	/* allocations */
	{
		path = realloc(rd->path, sizeof(*path) * (rd->h_ct));
		if (!path)
			return -1;

		next = realloc(rd->next, sizeof(*next) * (rd->h_ct));
		if (!next) {
			free(next);
			return -2;
		}

		size_t i;
		for (i = 0; i < rd->h_ct; i++) {
			path[i] = calloc(sizeof(*path[i]), (rd->h_ct));
			if (!path[i]) {
				return -3;
			}

			next[i] = calloc(sizeof(*next[i]), (rd->h_ct));
			if (!next[i]) {
				return -4;
			}
			size_t j;
			for (j = 0; j < rd->h_ct; j++) {
				next[i][j] = SIZE_MAX;
			}
		}
	}

	/* setup data in adjacency matrix */
	{
		size_t i;
		for (i = 0; i < rd->h_ct; i++) {
			struct _rt_host *host= rd->hosts[i];
			size_t j;
			for (j = 0; j < host->l_ct; j++) {
				struct _rt_link *l = &rd->hosts[i]->links[j];
				struct _rt_host *dst = l->dst;
				struct _rt_host **dstp = find_host_by_addr(
								rd->hosts,
								rd->h_ct,
								*dst->addr);

				size_t dst_i = dstp - rd->hosts;
				path[i][dst_i] = l->rtt_us;

				/* TODO: make bidirectionality assumption in
				 * the case where we lack information.
				 */
			}
		}
	}

	/* use Floyd-Warshal to find all pairs of shortest paths */
#if 0
 1 procedure FloydWarshallWithPathReconstruction ()
 2    for k := 1 to n
 3       for i := 1 to n
 4          for j := 1 to n
 5             if path[i][k] + path[k][j] < path[i][j] then
 6                path[i][j] := path[i][k]+path[k][j];
 7                next[i][j] := k;
 8
 9 procedure GetPath (i,j)
10    if path[i][j] equals infinity then
11      return "no path";
12    int intermediate := next[i][j];
13    if intermediate equals 'null' then
14      return " ";   /* there is an edge from i to j, with no vertices between */
15   else
16      return GetPath(i,intermediate) + intermediate + GetPath(intermediate,j);
#endif
	{
		size_t n = rd->h_ct;
		size_t k, j ,i;
		for (k = 0; k < n; k++) {
			for (i = 0; i < n; i++) {
				for (j = 0; i < n; j++) {
					if (!path[i][k] || !path[k][j]) {
						/* skip items which are
						 * disconnected (== 0)
						 */
						continue;
					}
					uint32_t x = path[i][k] + path[k][j];

					/* overflow possible */
					if (x < path[i][k] || x < path[k][j]) {
						x = UINT32_MAX;
					}

					if (x < path[i][j]) {
						path[i][j] = x;
						next[i][j] = k;
					}
				}
			}
		}
	}

	rd->path = path;
	rd->next = next;

	return 0;
}

static int host_alloc(ether_addr_t *mac, struct ipv4_host *ip_host,
		uint64_t ts_ms,
		bool dhost, struct _rt_host **host)
{
	struct _rt_host *h = malloc(sizeof(*h));
	if (!h) {
		return -1;
	}

	h->links = malloc(sizeof(*h->links) * RT_LINK_INIT);
	if (!h->links) {
		free(h);
		return -2;
	}

	h->l_ct = 0;
	h->l_mem = RT_LINK_INIT;

	h->ts_ms = ts_ms;

	h->is_dpeer = dhost;
	if (dhost) {
		h->addr = mac;
		h->host = ip_host;
	} else {
		h->addr = malloc(sizeof(*h->addr));
		if (!h->addr) {
			free(h->links);
			free(h);
			return -3;
		}

		h->host = malloc(sizeof(*h->host));
		if (!h->host) {
			free(h->addr);
			free(h->links);
			free(h);
			return -4;
		}
		*h->host = *ip_host;
		*h->addr = *mac;
	}

	*host = h;
	return 0;
}

static int link_add(struct _rt_host *src, struct _rt_host *dst,
		uint32_t rtt_us, uint64_t ts_ms)
{
	if ((src->l_ct + 1) > src->l_mem) {
		size_t mem = src->l_mem * RT_LINK_MULT;
		struct _rt_link *links = realloc(src->links,
				sizeof(*src->links) * mem);
		if (!links)
			return -1;

		src->l_mem = mem;
		src->links = links;
	}

	struct _rt_link l = {
		.dst = dst,
		.ts_ms = ts_ms,
		.rtt_us = rtt_us
	};
	src->links[src->l_ct] = l;
	src->l_ct++;

	qsort(src->links, src->l_ct, sizeof(*src->links), link_cmp_addr);

	return 0;
}

static int host_add(routing_t *rd, ether_addr_t *mac,
		struct ipv4_host *ip_host,
		uint64_t ts_ms, bool dhost)
{
	struct _rt_host **dup = find_host_by_addr(rd->hosts, rd->h_ct, *mac);

	/* dpeer already exsists. */
	if (dup) {
		return 1;
	}

	if ((rd->h_ct + 1) > rd->h_mem) {
		size_t mem = rd->h_mem * RT_HOST_MULT;

		struct _rt_host **hosts = realloc(rd->hosts,
				sizeof(*rd->hosts) * mem);
		if(!hosts) {
			return -2;
		}

		rd->h_mem = mem;
		rd->hosts = hosts;
	}

	struct _rt_host *nh;
	int ret = host_alloc(mac, ip_host, ts_ms, dhost, &nh);
	if (ret) {
		return -3;
	}

	rd->hosts[rd->h_ct] = nh;
	rd->h_ct++;

	/* resort the list */
	qsort(rd->hosts, rd->h_ct, sizeof(*rd->hosts), host_cmp_addr);

	return 0;
}

int rt_init(routing_t *rd)
{
	int ret = pthread_rwlock_init(&rd->lock, NULL);
	if (ret < 0)
		return ret;

	rd->hosts = malloc(sizeof(*rd->hosts) * RT_HOST_INIT);
	if (!rd->hosts)
		return -1;

	rd->h_ct = 0;
	rd->h_mem = RT_HOST_INIT;
	return 0;
}

void rt_destroy(routing_t *rd)
{
	free(rd->hosts);
	pthread_rwlock_destroy(&rd->lock);
}

/*
 * on failure, returns < 0.
 * if a duplicate exsists, returns 1.
 * otherwise, returns 0.
 */
int rt_lhost_add(routing_t *rd, ether_addr_t mac, struct ipv4_host *ip_host)
{
	pthread_rwlock_wrlock(&rd->lock);

	int p = host_add(rd, &mac, ip_host, 0, false);

	pthread_rwlock_unlock(&rd->lock);

	return p;
}

static void ihost_to_dhost(struct _rt_host *host, ether_addr_t *dhost_mac,
		struct ipv4_host *ip_host)
{
	if (!host->is_dpeer) {
		free(host->addr);
		free(host->host);
		host->host = ip_host;
		host->addr = dhost_mac;
		host->is_dpeer = true;
	}
}

int rt_dhost_add_link(routing_t *rd, ether_addr_t src_mac,
	ether_addr_t *dst_mac, struct ipv4_host *ip_host, uint32_t rtt_us)
{
	pthread_rwlock_wrlock(&rd->lock);

	struct _rt_host **src_host = find_host_by_addr(rd->hosts,
			rd->h_ct, src_mac);

	if (!src_host) {
		/* source host does not exsist */
		pthread_rwlock_unlock(&rd->lock);
		return -1;
	}
	struct _rt_host *sh = *src_host;


	struct _rt_link *stod = find_link_by_addr(sh->links,
			sh->l_ct, *dst_mac);


	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (!stod) {
		/* link does not exsist */

		struct _rt_host **dst_host = find_host_by_addr(rd->hosts,
				rd->h_ct, *dst_mac);
		if (!dst_host) {
			/* dst_host does not exsist, create */
			int ret = host_add(rd, dst_mac, ip_host, 0, true);
			if (ret) {
				return -2;
			}
		}

		/* dst_host does exsist, link up */
		int ret = link_add(*src_host, *dst_host, rtt_us, tv_ms(&tv));
		if (ret) {
			return -3;
		}

		/* make dst a dhost if it is not already */
		ihost_to_dhost(*dst_host, dst_mac, ip_host);
	} else {
		/* link  exsists. update rtt & ts */
		stod->rtt_us = rtt_us;
		stod->ts_ms = tv_ms(&tv);

		/* host should already be a dhost, ignoring */
	}

	int ret = compute_paths(rd);
	if (ret) {
		return -5;
	}
	pthread_rwlock_unlock(&rd->lock);
	return 0;
}

int rt_update_edges(routing_t *rd, struct _pkt_edge *edges, size_t e_ct)
{
	pthread_rwlock_wrlock(&rd->lock);

	compute_paths(rd);
	pthread_rwlock_unlock(&rd->lock);
	return -1;
}

int rt_remove_host(routing_t *rd, ether_addr_t mac)
{
	pthread_rwlock_wrlock(&rd->lock);
	pthread_rwlock_unlock(&rd->lock);
	return -1;
}

/* locking paired with rt_hosts_free due to dual owner of dpeer's mac */
int rt_dhosts_to_host(routing_t *rd,
		ether_addr_t src_mac, ether_addr_t cur_mac,
		ether_addr_t dst_mac, struct rt_hosts **res)
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

/**
 * rt_get_edges - gives the packed representation of the graph to the
 *                caller.
 * @rd            routing data from with the info is extracted
 * @edges         is set to the edges on success.
 * @e_ct          the count of edges (on success).
 *
 * return         negative on error. otherwise zero.
 */
int rt_get_edges(routing_t *rd, struct _pkt_edge **edges, size_t *e_ct)
{
	return -1;
}

/**
 * rt_edges_free - informs routing that we no longer require the edges it
 *		   gave us
 * @rd		routing data
 * @edges	edges returned by rt_get_edges.
 * @e_ct	number of edges
 */
void rt_edges_free(routing_t *rd, struct _pkt_edge *edges, size_t e_ct)
{
}
