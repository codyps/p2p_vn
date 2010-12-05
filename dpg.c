#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include "dpg.h"

/*0 succes, < 0 fail */
int dpg_init(dpg_t *g) {
	g = malloc(sizeof(struct direct_peer_group));
	if(!g) { return -1; }
	
	g->grp = malloc(5 * sizeof(struct direct_peer));
	g->num_peer = 0;
	g->size = 5;

	return 0;
}

/*0 succes, < 0 fail, 1 on duplicate */
int dpg_insert(dpg_t *g, direct_peer_t *dp) {
	direct_peer_t dup;
	dup = bsearch( , g->grp, g->num_peer, sizeof(struct direct_peer),
		
	
	
	if(g->num_peer < g->size - 1) {
		g->grp[num_peer] = dp;
		g->num_peer++;
	} else {
		g->size += 5;
		g->grp = realloc(g->grp, g->size * sizeof(struct direct_peer));
		if(!g->grp) {
			return -1;
		}
		g->grp[num_peer] = dp;
		g->num_peer++;
	}
	return 0;
}

/*0 succes, < 0 fail */
int dpg_remove(dpg_t *g, direct_peer_t *dp) {
	int x;
	int in;
	direct_peer_t temp;
	for(x = 0; x < g->count; x++) {
		if(cmp_mac(DPEER_MAC(g->grp[x]), DPEER_MAC(dp)) == 2) {
			g->grp[x] = g->grp[count -1];
			g->size--;
			g->count--;
			return 0;
		}
	}
	return -1;
}
