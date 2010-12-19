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

	pthread_rwlock_t lock;

	struct sockaddr_in l_addr;
};

#define DPG_LADDR(dpg) ((dpg)->l_addr)

int dpg_send_linkstate(dpg_t *g, routing_t *rd);

int dpg_init(dpg_t *g, char *ex_host, char *ex_port);
int dpg_insert(dpg_t *g, dp_t *dp);
int dpg_remove(dpg_t *g, dp_t *dp);

#endif
