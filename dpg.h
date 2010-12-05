#ifndef DPEER_H_
#define DPEER_H_ 1

#include <netinet/in.h> /* struct sockaddr_storage */
#include <stdbool.h>

#include "routing.h"
#include "dpeer.h"

typedef struct direct_peer_group {
	direct_peer_t **grp;
	struct sockaddr_in l_addr;
	int num_peer;
	int size;
} dpg_t;

#define DPG_LADDR(dpg) ((dpg)->l_addr)

/*not working yet */
#define for_each_dpeer(/*direct_peer_group */ dpg, /*direct_peer * */ dp) \
		for( dp = dpg->grp ;  < dpg->count ; dpg++ )

int dp_group_init(dpg_t *g);
int dp_group_insert(dpg_t *g, direct_peer_t *dp);
int dp_group_remove(dpg_t *g, direct_peer_t *dp);

#endif
