#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> /* getaddrinfo */

#include "debug.h"
#include "dpg.h"
#include "routing.h"

#include "stdparam.h"
#include "darray.h"

#if 0
static int dp_cmp(dp_t const *const *dp1, dp_t const *const *dp2)
{
#else
static int dp_cmp(void const *v1, void const *v2)
{
	dp_t const *const *dp1 = v1;
	dp_t const *const *dp2 = v2;
#endif

	const ether_addr_t *a1 = DP_MAC(*dp1);
	const ether_addr_t *a2 = DP_MAC(*dp2);
	return memcmp(a1, a2, ETH_ALEN);
}

static DEF_BSEARCH(dpg, dp_t *, dp_cmp)

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
	for (i = 0; i < g->dps.ct; i++) {
		dp_t *dp = g->dps.items[i];
		dp_send_linkstate(dp, edges, e_ct);
	}

	rt_edges_free(rd, edges, e_ct);

	pthread_rwlock_unlock(&g->lock);
	return 0;
}

#define DPG_INIT_SIZE 8

int dpg_init(dpg_t *g, char *ex_host, char *ex_port)
{
	int ret = pthread_rwlock_init(&g->lock, NULL);
	if (ret < 0)
		return -1;

	if (DA_INIT(&g->dps, DPG_INIT_SIZE)) {
		ret = -2;
		goto cleanup_mut;
	}

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
	DA_DESTROY(&g->dps);
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

	dp_t **dup = bsearch_dpg(&dp, g->dps.items, g->dps.ct);

	/* dpeer already exsists. */
	if (dup) {
		pthread_rwlock_unlock(&g->lock);
		return 1;
	}

	if (DA_ADD_TO_END(&g->dps, dp)) {
		pthread_rwlock_unlock(&g->lock);
		return -2;
	}

	/* resort the list */
	qsort(g->dps.items, g->dps.ct, sizeof(*g->dps.items), dp_cmp);

	pthread_rwlock_unlock(&g->lock);
	return 0;
}

int dpg_remove(dpg_t *g, dp_t *dp)
{
	int ret = pthread_rwlock_wrlock(&g->lock);
	if (ret < 0)
		return -1;

	dp_t **res = bsearch_dpg(&dp, g->dps.items, g->dps.ct);
	if (!res) {
		pthread_rwlock_unlock(&g->lock);
		return -2;
	}

	DA_REMOVE(g->dps.items, g->dps.ct, res);

	pthread_rwlock_unlock(&g->lock);
	return 0;
}

