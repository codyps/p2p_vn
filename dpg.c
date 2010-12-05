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
	/*re sort after search */
	if(g->num_peer) > 0) {
		dup = bsearch( dp, g->grp, g->num_peer, 
			sizeof(struct direct_peer), dp_cmp);
		qsort(g->grp, g->num_peer, sizeof(struct direct_peer), dp_cmp);
				
		if(dup) {
			return 1;
		}
		
	}
			
	
	
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

/*return 0 if equal*/
int dp_cmp(direct_peer_t p1, direct_peer_t p2) {
	int x;
	ether_addr_t a1 = DPEER_MAC(p1);
	ether_addr_t a2 = DPEER_MAC(p2);	
	for(x = 0; x < ETH_ALEN; x++) {
		if(a1[x] > a2[x]) {
			return 1;
		}
		if( a1[x] < a2[x]) {
			return -1;
		}
	}
	return 0;
}
