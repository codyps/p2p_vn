
#include <sys/types.h>
#include <sys/socket.h> /* bind */

#include <netdb.h> /* getaddrinfo */
#include <stdio.h> /* fprintf, stderr */
#include <unistd.h> /* getopt */
#include <stdlib.h> /* realloc */
#include <string.h> /* memset */
#include <errno.h> /* errno */
#include <stddef.h> /* offsetof */

/* open */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* tun */
#include <linux/if_tun.h>

/* netdevice (7) */
#include <sys/ioctl.h>
#include <net/if.h>

#include <pthread.h>

#define DEFAULT_PORT_STR "9004"

#include "debug.h"

#include "peer_proto.h"
#include "routing.h"
#include "vnet.h"
#include "dpeer.h"

/* data for each raw read thread */
struct vnet_reader_arg {
	vnet_t *vnet;
	routing_t *rd;
	dpg_t *dpg;
};

/* data for each peer_listener thread.
 *  in practice, we have only one */
struct peer_listener_arg {
	char *name;
	char *port;

	vnet_t *vnet;
	routing_t *rd;
	dpg_t *dpg;
};

/* Given a set pl->port, initializes the pl->sock (and pl->ai) */
static int peer_listener_bind(char *name, char *port, int *fd, struct addrinfo **ai)
{
	/* get data to bind */
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	/* FIXME: bound to IPv4 for now */
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

	int r = getaddrinfo(name,
			port, &hints,
			ai);
	if (r) {
		fprintf(stderr, "whoops: %s: %d %s\n",
				name,
				r, gai_strerror(r));
	}

	struct addrinfo *ail = *ai;
	int sock = socket(ail->ai_family,
			ail->ai_socktype, ail->ai_protocol);
	if (sock < 0) {
		WARN("socket: %s", strerror(errno));
		return errno;
	}

	if (bind(sock, ail->ai_addr, ail->ai_addrlen) < 0) {
		WARN("bind: %s", strerror(errno));
		return errno;
	}

	if (listen(sock, 0xF) == -1) {
		WARN("failed to listen for new peers: %s", strerror(errno));
		return errno;
	}

	*fd = sock;
	return 0;
}

int peer_listener(char *name, char *port,
		dpg_t *dpg, routing_t *rd, vnet_t *vn)
{
	int fd;
	struct addrinfo *ai;
	if (peer_listener_bind(name, port, &fd, &ai)) {
		DIE("peer_listener_bind failed.");
	}

	for(;;) {
		struct peer_reader_arg *pa = peer_listener_get_peer(pl);

		if (!pa) {
			DIE("peer_listener_get_peer failed");
		}

		/* start peer listener. req: peer_collection fully processed */
		dp_t *dp = malloc(sizeof(*dp));
		if (!dp) {
			DIE("malloc failed");
		}

		int ret = dpeer_init_incomming(dp, dpg, rd, vn, con_fd);
		if (ret) {
			DIE("dpeer_init_incomming failed");
		}
	}
}

static struct peer_reader_arg *peer_outgoing_mk(struct net_data *nd,
		char *name, char *port)
{
	struct peer_reader_arg *pa = malloc(sizeof(*pa));
	if (pa) {
		memset(pa, 0, sizeof(*pa));
		pa->name = name;
		pa->port = port;
		pa->net_data = nd;
	}
	return pa;
}

static struct peer_reader_arg *peer_incomming_mk(struct net_data *nd,
		size_t addrlen)
{
	struct peer_reader_arg *pa = malloc(sizeof(*pa));
	if (!pa) {
		return NULL;
	}
	memset(pa, 0, sizeof(*pa));

	pa->ai = malloc(sizeof(*pa->ai));
	if (!pa->ai) {
		free(pa);
		return NULL;
	}
	memset(pa->ai, 0, sizeof(*pa->ai));

	pa->ai->ai_addrlen = addrlen;
	pa->ai->ai_addr = malloc(addrlen);
	if (!pa->ai->ai_addr) {
		free(pa->ai);
		free(pa);
		return NULL;
	}

	pa->net_data = nd;
	return pa;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s <port> <local interface>\n"
		"       %s <remote host> <remote port> <local interface>\n"
		, name, name);
	exit(EXIT_FAILURE);
}

static void *th_net_reader(void *arg)
{
	struct net_reader_arg *rn = arg;

	for(;;) {
		struct packet packet;
		packet.len = sizeof(packet.data);
		int r = net_recv_packet(rn->net_data, packet.data,
				&packet.len);

		if (r) {
			WARN("bleh %s", strerror(r));
			return NULL;
		}

		r = peer_send_packet(rn->peer_sock, packet.data, packet.len);
		if (r) {
			WARN("%s", strerror(r));
			return NULL;
		}
	}
	return rn;
}

static void *th_peer_reader(void *arg)
{
	struct peer_reader_arg *pd = arg;

	for(;;) {
		struct packet packet;
		packet.len = sizeof(packet.data);

		int r = peer_recv_packet(pd->peer_sock, packet.data,
			&packet.len);
		if (r < 0) {
			/* XXX: on client & server ctrl-c this fires */
			WARN("Failed to recieve packet. %s", strerror(-r));
			return NULL;
		} else if (r == 1) {
			WARN("remote peer disconnected, cleanup.");
			return NULL;
		}
		r = net_send_packet(pd->net_data, packet.data,
			packet.len);
		if (r) {
			WARN("Failed to send packet. %s", strerror(r));
			return NULL;
		}
	}
	return pd;
}


static struct peer_reader_arg *peer_listener_get_peer(
		struct peer_listener_arg *pl)
{
	struct peer_reader_arg *peer = peer_incomming_mk(pl->net_data,
		sizeof(struct sockaddr_storage));

	if (!peer) {
		WARN("blah");
		return NULL;
	}

	/* wait for new connections */
	peer->peer_sock = accept(pl->listen_sock,
			peer->ai->ai_addr, &peer->ai->ai_addrlen);

	if (peer->peer_sock == -1) {
		/* FIXME: deallocate peer */
		WARN("failure to accept new peer: %s", strerror(errno));
		return NULL;
	}

	/* XXX: populate peer data
	 * specifically, peer->ai (addrinfo) needs filling */

	return peer;
}

static int main_listener(char *ifname, char *name, char *port)
{
	struct net_data nd;
	int nret;
	nret = net_init(&nd, ifname);
	if(nret < 0) {
		DIE("net init failed.");
	}

	struct net_reader_arg nr_ = {
		.net_data = &nd,
		.peer_sock = -1
	}, *nr = &nr_;


	struct peer_listener_arg pl_ = {
		.name = name, /* bind to all */
		.port = port,
		.net_data = &nd
	}, *pl = &pl_;


}

static int main_connector(char *ifname, char *host, char *port)
{
	struct net_data nd;
	if(net_init(&nd, ifname)) {
		DIE("net init.");
	}

	struct net_reader_arg nr_ = {
		.net_data = &nd,
		.peer_sock = -1
	}, *nr = &nr_;

	struct peer_reader_arg *peer = peer_outgoing_mk(&nd, host,
			port);
	if (!peer)
		DIE("WTH");

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	int r = getaddrinfo(peer->name,
			peer->port, &hints,
			&peer->ai);
	if (r) {
		WARN("getaddrinfo: %s: %d %s",
				peer->name,
				r, gai_strerror(r));
		return -1;
	}

	/* connect to peer */
	peer->peer_sock = socket(peer->ai->ai_family,
			peer->ai->ai_socktype, peer->ai->ai_protocol);
	if (peer->peer_sock < 0) {
		WARN("socket: %s", strerror(errno));
		return errno;
	}

	if (connect(peer->peer_sock, peer->ai->ai_addr,
				peer->ai->ai_addrlen) < 0) {
		WARN("connect: %s", strerror(errno));
		return errno;
	}

	nr->peer_sock = peer->peer_sock;

	/* spawn */
	pthread_t peer_pth, net_pth;
	pthread_create(&peer_pth, NULL, th_peer_reader, peer);
	pthread_create(&net_pth, NULL, th_net_reader, nr);

	pthread_join(peer_pth, NULL);
	pthread_join(net_pth, NULL);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 3) {
		/* listener <ifname> <lhost> <lport> */
		return main_listener(argv[2], NULL, argv[1]);
	} else if (argc == 4) {
		/* connector <ifname> <rhost> <rport> */
		return main_connector(argv[3], argv[1], argv[2]);
	} else {
		usage((argc>0)?argv[0]:"L203");
	}
	return 0;
}

