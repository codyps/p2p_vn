#ifndef DPG_H_
#define DPG_H_ 1

#include <netinet/in.h> /* struct sockaddr_storage */
#include <stdbool.h>

typedef struct direct_peer_group dpg_t;

#include "routing.h"
#include "dpeer.h"

struct direct_peer_group {
	dp_t **dps;
	size_t dp_ct;
	size_t dp_mem;

	struct sockaddr_in l_addr;
};

#define DPG_LADDR(dpg) ((dpg)->l_addr)

/**
 * for_each_dpeer - allow an action to be taken on each dpeer in a dpeer group
 * @dpg:        (dpg_t *) the direct peer group containing the dpeers to be iterated over.
 * @dpp:        (dp_t **) a pointer to a direct peer pointer
 *
 */
#define for_each_dpeer(dpg, dp) \
		for( dp = dpg->dps ; dp < (dpg->dps + dpg->dp_ct); dp++ )

int dpg_init(dpg_t *g, struct sockaddr_in *l_addr);
int dpg_insert(dpg_t *g, dp_t *dp);
int dpg_remove(dpg_t *g, dp_t *dp);

#endif
