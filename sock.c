
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

static int peer_listener_get_peer(int listen_fd, struct sockaddr_in *addr, socklen_t *addrlen)
{
	if (!peer) {
		WARN("blah");
		return NULL;
	}

	/* wait for new connections */
	int peer_fd = accept(listen_fd,
			addr, addrlen);

	if (peer_fd == -1) {
		WARN("failure to accept new peer: %s", strerror(errno));
		return NULL;
	}

	return peer_fd;
}

static int peer_listener(char *name, char *port,
		dpg_t *dpg, routing_t *rd, vnet_t *vn)
{
	int fd;
	struct addrinfo *ai;
	if (peer_listener_bind(name, port, &fd, &ai)) {
		DIE("peer_listener_bind failed.");
	}

	for(;;) {
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int con_fd = peer_listener_get_peer(fd, &addr, &addrlen);

		if (!pa) {
			DIE("peer_listener_get_peer failed");
		}

		/* start peer listener. req: peer_collection fully processed */
		dp_t *dp = malloc(sizeof(*dp));
		if (!dp) {
			DIE("malloc failed");
		}

		int ret = dpeer_init_incomming(dp, dpg, rd, vn, con_fd, &addr);
		if (ret) {
			DIE("dpeer_init_incomming failed");
		}
	}
}

static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s <local vnet> <lport> [ <remote host> <remote port> ]\n"
		, name, name);
	exit(EXIT_FAILURE);
}

#define DATA_MAX_LEN 2048
static void *th_vnet_reader(void *arg)
{
	struct vnet_reader_arg *vra = arg;

	void *data = malloc(DATA_MAX_LEN);
	for(;;) {
		size_t pkt_len = DATA_MAX_LEN;
		int r = vnet_recv(vra->vnet, data,
				&pkt_len);
		if (r < 0) {
			WARN("vnet_recv: %s", strerror(r));
			return NULL;
		}

		struct ether_header *eh = data;
		struct rt_hosts *hosts;
		r = rt_dhosts_to_host(vra->rd,
				VNET_MAC(vra->vnet), VNET_MAC(vra->vnet), eh->ether_dhost,
				&hosts);
		if (r < 0) {
			WARN("rt_dhosts_to_host %s", strerror(r));
			return NULL;
		}

		struct rt_hosts *nhost = hosts;
		while(nhost) {
			r = dp_send_data(dp_from_eth(nhost->addr), data, len);
			if (r < 0) {
				WARN("%s", strerror(r));
				return NULL;
			}
			nhost = nhost->next;
		}

		rt_hosts_free(hosts);
	}
	return rn;
}

static int main_listener(char *ifname, char *lname, char *lport, char *rname, char *rport)
{
	vnet_t vnet;
	dpg_t dpg;
	routing_t rd;

	int ret = vnet_init(&vnet, ifname);
	if(ret < 0) {
		DIE("vnet_init failed.");
	}

	ret = dpg_init(&dpg);
	if(ret < 0) {
		DIE("dpg_init failed.");
	}

	ret = rt_init(&rd);
	if(ret < 0) {
		DIE("rd_init failed.");
	}

	/* vnet listener spawn */
	{
		struct vnet_reader_arg vra = {
			.dpg = &dpg,
			.rd = &rd,
			.vnet = &vnet,
		};

		pthread_t vnet_th;
		ret = pthread_create(&vnet_th, NULL, vnet_reader_th, vnet_reader_arg);
		if (ret) {
			DIE("pthread_create vnet_th failed.");
		}

		ret = pthread_detach(vnet_th);
		if (ret) {
			DIE("pthread_detach vnet_th failed.");
		}
	}

	/* inital dpeer spawn */
	if (rname && rport) {
		dp_t *dp = malloc(sizeof(*dp));
		if (!dp) {
			DIE("initial dp alloc failed.");
		}

		ret = dp_init_initial(dp, &dpg, &rd, &vnet, rname, rport)
		if (ret < 0) {
			DIE("initial dp init failed.");
		}
	}

	return peer_listener(lname, lport, &dpg, &rd, &vnet);
}


int main(int argc, char **argv)
{
	if (argc == 4) {
		/* listener <ifname> <lhost> <lport> */
		return main_listener(argv[2], NULL, argv[1]);
	} else if (argc == 6) {
		/* connector <ifname> <lhost> <lport> <rhost> <rport> */
		return main_listener(argv[3], argv[1], argv[2]);
	} else {
		usage((argc>0)?argv[0]:"L203");
	}
	return 0;
}

