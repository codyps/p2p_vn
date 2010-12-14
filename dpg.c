#include <stdlib.h>
#include <string.h>

#include "dpg.h"

static int dp_cmp(const void *kp1_v, const void *kp2_v)
{
	const dp_t *const *dp1 = kp1_v;
	const dp_t *const *dp2 = kp2_v;

	const ether_addr_t *a1 = &DPEER_MAC(*dp1);
	const ether_addr_t *a2 = &DPEER_MAC(*dp2);
	return memcmp(a1, a2, ETH_ALEN);
}

#define DPG_INIT_SIZE 5
#define DPG_INC_MULT 2

int dpg_init(dpg_t *g, struct sockaddr_in *l_addr)
{
	int ret = pthread_mutex_init(&g->lock, NULL);
	if (ret < 0)
		return -1;

	g->dps = malloc(DPG_INIT_SIZE * sizeof(*g->dps));
	if (!g->dps) {
		pthread_mutex_destroy(&g->lock);
		return -2;
	}

	g->dp_ct = 0;
	g->dp_mem = DPG_INIT_SIZE;
	g->l_addr = *l_addr;
	return 0;
}

/*
 * on failure, returns < 0.
 * if a duplicate exsists, returns 1.
 * otherwise, returns 0.
 */
int dpg_insert(dpg_t *g, dp_t *dp)
{
	int ret = pthread_mutex_lock(&g->lock);
	if (ret < 0)
		return -1;

	dp_t **dup = bsearch(&dp, g->dps, g->dp_ct, sizeof(*g->dps),
			dp_cmp);

	/* dpeer already exsists. */
	if(dup) {
		pthread_mutex_unlock(&g->lock);
		return 1;
	}

	if (g->dp_ct + 1 > g->dp_mem) {
		/* we need more memory to fit the pointer */
		size_t n_dp_mem = g->dp_mem * DPG_INC_MULT;
		dp_t **dps = realloc(g->dps, n_dp_mem * sizeof(*g->dps));
		if(!dps) {
			pthread_mutex_unlock(&g->lock);
			return -2;
		}
		g->dp_mem = n_dp_mem;
		g->dps = dps;
	}

	g->dps[g->dp_ct] = dp;
	g->dp_ct++;

	/* resort the list */
	qsort(g->dps, g->dp_ct, sizeof(*g->dps), dp_cmp);

	pthread_mutex_unlock(&g->lock);
	return 0;
}

int dpg_remove(dpg_t *g, dp_t *dp)
{
	int ret = pthread_mutex_lock(&g->lock);
	if (ret < 0)
		return -1;

	dp_t ** res = bsearch(&dp, g->dps, g->dp_ct, sizeof(*g->dps), dp_cmp);
	if (!res) {
		pthread_mutex_unlock(&g->lock);
		return -2;
	}

	/* XXX: check this math */
	size_t ct_to_end = res - g->dps;
	memmove(res, res+1, ct_to_end * sizeof(*g->dps));

	pthread_mutex_unlock(&g->lock);
	return 0;
}

