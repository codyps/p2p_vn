#ifndef DPG_H_
#define DPG_H_ 1

#include <netinet/in.h> /* struct sockaddr_storage */
#include <stdbool.h>

typedef struct direct_peer_group dpg_t;

#include "routing.h"
#include "dpeer.h"

struct direct_peer_group {
	dp_t **grp;
	struct sockaddr_in l_addr;
	int num_peer;
	int size;
};

#define DPG_LADDR(dpg) ((dpg)->l_addr)

/*not working yet */
#define for_each_dpeer(/*direct_peer_group * */ dpg, /* direct_peer ** */ dp) \
		for( dp = dpg->grp ; dp < (dpg->grp + dpg->count); dp++ )

int dpg_init(dpg_t *g);
int dpg_insert(dpg_t *g, dp_t *dp);
int dpg_remove(dpg_t *g, dp_t *dp);

#endif
