#include "dpeer.h"




void *dp_out_th(void *dp_v)
{

}

void *dp_in_th(void *dp_v)
{

}

void *dp_route_th(void *dp_v)
{
	struct direct_peer *dp = dp_v;

	pthread_create(&dp->dp_th, NULL, dp_out_th, dp);


	for(;;) {
		/* check for packets on in queue */
		/* if found, ask route for a route */
			/* add the packets to the out queue of the next
			 * nodes */

		/* check if we're still in busieness */
			/* if no, wait for death */
				/* free reasources & exit */
	}
}


int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd)
{
	memset(dp, 0, sizeof(dp));

	dp->con_fd = con_fd;

	memcpy(dp->remote_mac, mac, sizeof(dp->remote_mac));

	pthread_mutex_init(&dp->dlock_out, NULL);
	pthread_mutex_init(&dp->dlock_in, NULL);

	pthread_create(&dp->th_route, NULL, dp_route_th, dp);

	return 0;
}
