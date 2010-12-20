#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> /* getaddrinfo */

#include "debug.h"
#include "dpg.h"
#include "routing.h"

static int dp_cmp(const void *kp1_v, const void *kp2_v)
{
	const dp_t *const *dp1 = kp1_v;
	const dp_t *const *dp2 = kp2_v;

	const ether_addr_t *a1 = DP_MAC(*dp1);
	const ether_addr_t *a2 = DP_MAC(*dp2);
	return memcmp(a1, a2, ETH_ALEN);
}

int dpg_send_linkstate(dpg_t *g, routing_t *rd)
{
	int ret = pthread_rwlock_rdlock(&g->lock);
	if (ret < 0)
		return -1;

	struct _pkt_edge *edges;
	size_t e_ct;
	ret = rt_get_edges(rd, &edges, &e_ct);
	if (ret) {
		pthread_rwlock_unlock(&g->lock);
		return -2;
	}

	size_t i;
	for (i = 0; i < g->dp_ct; i++) {
		dp_t *dp = g->dps[i];
		dp_send_linkstate(dp, edges, e_ct);
	}

	pthread_rwlock_unlock(&g->lock);
	return 0;
}

#define DPG_INIT_SIZE 5
#define DPG_INC_MULT 2

int dpg_init(dpg_t *g, char *ex_host, char *ex_port)
{
	int ret = pthread_rwlock_init(&g->lock, NULL);
	if (ret < 0)
		return -1;

	g->dps = malloc(DPG_INIT_SIZE * sizeof(*g->dps));
	if (!g->dps) {
		ret = -2;
		goto cleanup_mut;
	}

	g->dp_ct = 0;
	g->dp_mem = DPG_INIT_SIZE;

	{
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICSERV;

		struct addrinfo *ai;
		ret = getaddrinfo(ex_host,
				ex_port, &hints,
				&ai);
		if (ret) {
			WARN("getaddrinfo: %s: %d %s",
				ex_host, ret, gai_strerror(ret));
			ret = -3;
			goto cleanup_dps;
		}

		memcpy(&g->l_addr, ai->ai_addr, sizeof(g->l_addr));

		freeaddrinfo(ai);
	}

	return 0;

cleanup_dps:
	free(g->dps);
cleanup_mut:
	pthread_rwlock_destroy(&g->lock);
	return ret;
}

/*
 * on failure, returns < 0.
 * if a duplicate exsists, returns 1.
 * otherwise, returns 0.
 */
int dpg_insert(dpg_t *g, dp_t *dp)
{
	int ret = pthread_rwlock_wrlock(&g->lock);
	if (ret < 0)
		return -1;

	dp_t **dup = bsearch(&dp, g->dps, g->dp_ct, sizeof(*g->dps),
			dp_cmp);

	/* dpeer already exsists. */
	if(dup) {
		pthread_rwlock_unlock(&g->lock);
		return 1;
	}

	if (g->dp_ct + 1 > g->dp_mem) {
		/* we need more memory to fit the pointer */
		size_t n_dp_mem = g->dp_mem * DPG_INC_MULT;
		dp_t **dps = realloc(g->dps, n_dp_mem * sizeof(*g->dps));
		if(!dps) {
			pthread_rwlock_unlock(&g->lock);
			return -2;
		}
		g->dp_mem = n_dp_mem;
		g->dps = dps;
	}

	g->dps[g->dp_ct] = dp;
	g->dp_ct++;

	/* resort the list */
	qsort(g->dps, g->dp_ct, sizeof(*g->dps), dp_cmp);

	pthread_rwlock_unlock(&g->lock);
	return 0;
}

int dpg_remove(dpg_t *g, dp_t *dp)
{
	int ret = pthread_rwlock_wrlock(&g->lock);
	if (ret < 0)
		return -1;

	dp_t ** res = bsearch(&dp, g->dps, g->dp_ct, sizeof(*g->dps), dp_cmp);
	if (!res) {
		pthread_rwlock_unlock(&g->lock);
		return -2;
	}

	/* XXX: check this math */
	size_t ct_to_end = res - g->dps;
	memmove(res, res+1, ct_to_end * sizeof(*g->dps));

	pthread_rwlock_unlock(&g->lock);
	return 0;
}

