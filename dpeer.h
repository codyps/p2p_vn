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

#define DPEER_MAC(dp) ((dp)->remote_mac)

struct direct_peer {
	int con_fd;
	pthread_mutex_t wlock;

	pthread_t dp_th;

	ether_addr_t remote_mac;
	struct sockaddr_in addr;

	dpg_t *dpg;
	routing_t *rd;
	vnet_t *vnet;

	/* the currently outstanding probe req.
	 * we only support 1 for now */
	uint16_t probe_seq;

	struct timeval probe_send_time;
	struct timeval rtt_tv;
	uint32_t rtt_us;
};

typedef uint32_t __be32;
typedef uint16_t __be16;

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define dp_from_eth(eth) container_of(eth, struct direct_peer, remote_mac)

/* sends a data packet.
 * for use by the vnet thread
 */
int dp_send_data(dp_t *dp, void *data, size_t len);

/* each dp_init thread initializes the dp data structure to a degree,
 * and spawns a thread to complete initialization.
 * that init-specific thread goes on to call the general peer thread
 */

/* for the command line specified peer */
int dp_create_initial(dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		char *host, char *port);

/* peers recieved via link state packets. */
int dp_create_linkstate(dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		ether_addr_t mac, __be32 inet_addr, __be16 inet_port);

/* incomming peer connections to the peer_listener */
int dp_create_incoming(dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		int fd, struct sockaddr_in *addr);

#endif
