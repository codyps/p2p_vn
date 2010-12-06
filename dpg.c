#include <stdlib.h>
#include <string.h>

#include "dpg.h"

static int dp_cmp(const void *key_v, const void *array_member_v)
{
	dp_t *key = key_v;
	dp_t **array_member = array_member_v;

	ether_addr_t *a1 = &DPEER_MAC(key);
	ether_addr_t *a2 = &DPEER_MAC(*array_member);
	return memcmp(a1, a2, ETH_ALEN);
}

#define DPG_INIT_SIZE 5
#define DPG_INC_MULT 2

/*0 succes, < 0 fail */
int dpg_init(dpg_t *g, struct sockaddr_in *l_addr)
{
	g->dps = malloc(DPG_INIT_SIZE * sizeof(*g->dps));
	if (!g->dps)
		return -1;

	g->dp_ct = 0;
	g->dp_mem = DPG_INIT_SIZE;
	g->l_addr = *l_addr;
	return 0;
}

/*0 succes, < 0 fail, 1 on duplicate */
int dpg_insert(dpg_t *g, dp_t *dp)
{
	dp_t **dup = bsearch(dp, g->dps, g->dp_ct, sizeof(*g->dps),
			(__compar_fn_t)dp_cmp);

	/* dpeer already exsists. */
	if(dup)
		return 1;

	qsort(g->dps, g->dp_ct, sizeof(*g->dps), dp_cmp);

	if(g->dp_ct < g->dp_mem - 1) {
		/* it fits in our currently allocated space. */
		g->dps[g->dp_ct] = dp;
		g->dp_ct++;
	} else {
		/* we need more memory to fit the pointer */
		g->dp_mem *= DPG_INC_MULT;
		g->dps = realloc(g->dps, g->dp_mem * sizeof(*g->dps));
		if(!g->dps) {
			return -1;
		}
		g->dps[g->dp_ct] = dp;
		g->dp_ct++;
	}

	return 0;
}

/*0 succes, < 0 fail */
int dpg_remove(dpg_t *g, dp_t *dp)
{
	int x;
	int in;
	dp_t *temp;

	dp_t ** res = bsearch(dp, g->dps, g->dp_ct, sizeof(*g->dps), dp_cmp);
	if (!res) {
		return -1;
	}

	size_t ct_to_end = res - g->dps;
	memmove(res, res+1, ct_to_end * sizeof(*g->dps));

	return 0;
}

