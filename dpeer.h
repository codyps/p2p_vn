#ifndef DPEER_H_
#define DPEER_H_ 1

#include <stddef.h> /* offsetof */
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

typedef struct direct_peer dp_t;

#include "routing.h"
#include "dpg.h"
#include "vnet.h"
#include "pcon.h"
#include "util.h"

#define DP_MAC(dp) (&(dp)->remote_host.mac)
#define DP_HOST(dp)   (&(dp)->remote_host)

struct direct_peer {
	int con_fd;
	pthread_mutex_t wlock;

	pthread_t dp_th;

	struct ipv4_host remote_host;

	dpg_t *dpg;
	routing_t *rd;
	vnet_t *vnet;
	pcon_t *pc;

	/* the currently outstanding probe req.
	 * we only support 1 for now */
	uint16_t probe_seq;

	struct timeval probe_send_time;
	struct timeval rtt_tv;
	uint32_t rtt_us;
};

#define dp_from_ip_host(ip_host) container_of(ip_host, dp_t, remote_host)

/* i use this in routing too. */
void pkt_ipv4_unpack(const struct _pkt_ipv4_host *pip, ether_addr_t *mac,
		struct sockaddr_in *addr);

/* sends a data packet.
 * for use by the vnet thread.
 */
int dp_send_data(dp_t *dp, void *data, size_t len);

/* sends a links state packet
 * for use by dpg_send_linkstate. */
int dp_send_linkstate(dp_t *dp, struct _pkt_edge *edges, size_t e_ct);

/* each dp_init thread initializes the dp data structure to a degree,
 * and spawns a thread to complete initialization.
 * that init-specific thread goes on to call the general peer thread
 */

/* for the command line specified peer */
int dp_create_initial(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc,
		char *host, char *port);

/* peers recieved via link state packets. */
int dp_create_linkstate(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc,
		ether_addr_t mac, struct sockaddr_in addr);

/* incomming peer connections to the peer_listener */
int dp_create_incoming(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc,
		int fd, struct sockaddr_in *addr);

#endif
