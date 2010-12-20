#include <stdlib.h>

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "routing.h"
#include "dpeer.h"
#include "util.h"

#define RT_HOST_INIT 8
#define RT_LINK_INIT 8
#define RT_HOST_MULT 2
#define RT_LINK_MULT 2



static int ipv4_cmp_mac(struct ipv4_host *h1, struct ipv4_host *h2)
{
	return memcmp(&h1->mac, &h2->mac, ETH_ALEN);
}

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

static void pkt_ipv4_pack(struct _pkt_ipv4_host *ph, struct ipv4_host *h)
{
	ph->ip = htonl(h->in.sin_addr.s_addr);
	ph->port = htons(h->in.sin_port);
	memcpy(ph->mac, h->mac.addr, ETH_ALEN);
}

static int update_exported_edges(routing_t *rd)
{
	struct _pkt_edge *edges = rd->edges;
	size_t e_ct = 0;
	size_t e_mem = rd->e_mem;
	size_t i;
	for (i = 0; i < rd->h_ct; i++) {
		struct _rt_host *h = rd->hosts[i];
		struct _pkt_ipv4_host src;
		pkt_ipv4_pack(&src, h->host);

		size_t j;
		for (j = 0; j < h->l_ct; j ++) {
			if ((e_ct + 1) > e_mem) {
				e_mem = 2 * e_mem + 8;
				edges = realloc(edges, sizeof(*edges) * e_mem);
				if (!edges)
					return -1;
			}

			struct _rt_link *link = &h->links[j];
			edges[e_ct].src = src;
			pkt_ipv4_pack(&edges[e_ct].dst, link->dst->host);

			edges[e_ct].rtt_us = htonl(link->rtt_us);
			edges[e_ct].ts_ms = htonll(link->ts_ms);

			e_ct ++;
		}
	}

	rd->e_mem = e_mem;
	rd->e_ct = e_ct;
	rd->edges = edges;

	return 0;
}

static int trim_disjoint_hosts(routing_t *rd)
{
	/* TODO: find hosts which lack outgoing (and incomming?)
	 * links and remove them */
	return -1;
}

static int update_cache(routing_t *rd)
{
	int ret = trim_disjoint_hosts(rd);
	if (ret < 0)
		return ret;
	ret = compute_paths(rd);
	if (ret < 0)
		return ret;

	ret = update_exported_edges(rd);
	if (ret < 0)
		return ret;
	return 0;
}

static int host_alloc(ether_addr_t *mac, struct ipv4_host *ip_host,
		enum host_type type, struct _rt_host **host)
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
	h->l_max_ts_ms = 0;

	h->type = type;
	if (type == HT_DIRECT) {
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


	if (ts_ms > src->l_max_ts_ms) {
		src->l_max_ts_ms = ts_ms;
	}

	qsort(src->links, src->l_ct, sizeof(*src->links), link_cmp_addr);

	return 0;
}

static int host_add(routing_t *rd, ether_addr_t *mac,
		struct ipv4_host *ip_host, enum host_type type,
		struct _rt_host **res)
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
	int ret = host_alloc(mac, ip_host, type, &nh);
	if (ret) {
		return -3;
	}

	rd->hosts[rd->h_ct] = nh;
	rd->h_ct++;

	/* resort the list */
	qsort(rd->hosts, rd->h_ct, sizeof(*rd->hosts), host_cmp_addr);

	if (res) {
		*res = nh;
	}

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

	rd->path = NULL;
	rd->next = NULL;
	rd->edges = NULL;
	rd->e_ct = 0;
	rd->e_mem = 0;

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

	int p = host_add(rd, &mac, ip_host, HT_LOCAL, NULL);

	pthread_rwlock_unlock(&rd->lock);

	return p;
}

static void ihost_to_dhost(struct _rt_host *host, ether_addr_t *dhost_mac,
		struct ipv4_host *ip_host)
{
	if (host->type != HT_DIRECT) {
		free(host->addr);
		free(host->host);
		host->host = ip_host;
		host->addr = dhost_mac;
		host->type = HT_DIRECT;
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
			int ret = host_add(rd, dst_mac, ip_host, HT_DIRECT, NULL);
			if (ret) {
				pthread_rwlock_unlock(&rd->lock);
				return -2;
			}
		}

		/* dst_host does exsist, link up */
		int ret = link_add(*src_host, *dst_host, rtt_us, tv_ms(&tv));
		if (ret) {
			pthread_rwlock_unlock(&rd->lock);
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

	int ret = update_cache(rd);
	if (ret) {
		pthread_rwlock_unlock(&rd->lock);
		return -5;
	}
	pthread_rwlock_unlock(&rd->lock);
	return 0;
}

static int pkt_edges_cmp_src(const void *v1, const void *v2)
{
	const struct _pkt_edge *e1 = v1;
	const struct _pkt_edge *e2 = v2;

	int ret = memcmp(e1->src.mac, e2->src.mac, ETH_ALEN);
	if (!ret) {
		if (e1->ts_ms > e2->ts_ms)
			return -1;
		else if (e1->ts_ms < e2->ts_ms)
			return 1;
		else
			return 0;
	}
	return ret;
}

int rt_update_edges(routing_t *rd, struct _pkt_edge *edges, size_t e_ct)
{
	pthread_rwlock_wrlock(&rd->lock);

	qsort(edges, e_ct, sizeof(*edges), pkt_edges_cmp_src);

	size_t i;

	struct ipv4_host cur_ip_src = {};
	struct _rt_host *cur_host_src = NULL;

	bool cont_to_new_src = false;

	for (i = 0; i < e_ct; i++) {
		struct _pkt_edge *e = &edges[i];
		struct _pkt_ipv4_host *psrc = &e->src;
		struct _pkt_ipv4_host *pdst = &e->dst;
		uint32_t rtt_us = ntohl(e->rtt_us);
		uint64_t ts_ms = ntohll(e->ts_ms);

		struct ipv4_host src, dst;

		pkt_ipv4_unpack(psrc, &src.mac, &src.in);
		pkt_ipv4_unpack(pdst, &dst.mac, &dst.in);

		if (cont_to_new_src) {
			if (!ipv4_cmp_mac(&src, &cur_ip_src))
				continue;
			else
				cont_to_new_src = false;
		}

		if ( !cur_host_src || ipv4_cmp_mac(&src, &cur_ip_src) ) {
			/* we are on a new source */
			cur_ip_src = src;

			struct _rt_host **hsrcp = find_host_by_addr(rd->hosts,
					rd->h_ct, cur_ip_src.mac);

			if (!hsrcp) {
				/* new source host does not exsist, create it. */
				int ret = host_add(rd, &cur_ip_src.mac, &cur_ip_src,
						HT_NORMAL, &cur_host_src);
				if (ret) {
					pthread_rwlock_unlock(&rd->lock);
					return -1;
				}
			} else {
				/* new source host does exsist, if it is not
				 * a lhost, wipe it's links if the ones
				 * we have are newer. */
				cur_host_src = *hsrcp;

				if (cur_host_src->type != HT_LOCAL &&
						cur_host_src->l_max_ts_ms < ts_ms) {
					cur_host_src->l_ct = 0;
				} else {
					/* advance to a different src host */
					cont_to_new_src = true;
					continue;
				}
			}
		}

		/* find destination. */
		struct _rt_host **dst_hostp = find_host_by_addr(rd->hosts,
				rd->h_ct, dst.mac);

		struct _rt_host *dst_host;
		if (!dst_hostp) {
			host_add(rd, &dst.mac, &dst, HT_NORMAL, &dst_host);
		} else {
			dst_host = *dst_hostp;
		}

		/* add link */
		int ret = link_add(cur_host_src, dst_host, rtt_us, ts_ms);
		if (ret) {
			pthread_rwlock_unlock(&rd->lock);
			return -2;
		}
	}

	int ret = update_cache(rd);
	if (ret) {
		pthread_rwlock_unlock(&rd->lock);
		return -5;
	}
	pthread_rwlock_unlock(&rd->lock);
	return 0;
}

void link_remove(struct _rt_host *src, struct _rt_link *link)
{
	src->l_ct --;
	size_t ct_ahead = link - src->links;
	size_t ct_to_end = src->l_ct - ct_ahead;

	memmove(src->links, src->links + 1, ct_to_end * sizeof(*src->links));
}

int rt_remove_dhost(routing_t *rd, ether_addr_t lmac, ether_addr_t *dmac)
{
	pthread_rwlock_wrlock(&rd->lock);

	struct _rt_host **sh_ = find_host_by_addr(rd->hosts, rd->h_ct, lmac);
	if (!sh_) {
		pthread_rwlock_unlock(&rd->lock);
		return -10;
	}
	struct _rt_host *sh = *sh_;

	struct _rt_link *l = find_link_by_addr(sh->links, sh->l_ct, *dmac);
	if (!l) {
		pthread_rwlock_unlock(&rd->lock);
		return 1;
	}

	struct _rt_host *h = l->dst;

	if (h->type != HT_DIRECT) {
		pthread_rwlock_unlock(&rd->lock);
		return -5;
	}

	struct ipv4_host *iph = malloc(sizeof(*iph));
	if (!iph) {
		pthread_rwlock_unlock(&rd->lock);
		return -3;
	}

	*iph = *h->host;
	h->host = iph;
	h->type = HT_NORMAL;

	link_remove(sh, l);

	int ret = update_cache(rd);
	if (ret) {
		pthread_rwlock_unlock(&rd->lock);
		return -2;
	}
	pthread_rwlock_unlock(&rd->lock);
	return 0;
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
