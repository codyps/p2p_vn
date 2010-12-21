
#include <sys/types.h>
#include <sys/socket.h> /* bind */

#include <netdb.h> /* getaddrinfo */
#include <stdio.h> /* fprintf, stderr */
#include <unistd.h> /* getopt */
#include <stdlib.h> /* realloc */
#include <string.h> /* memset */
#include <errno.h> /* errno */
#include <stddef.h> /* offsetof */


#include <pthread.h>

#define DEFAULT_PORT_STR "9004"

#include "debug.h"
#include "peer_proto.h"
#include "dpeer.h"
#include "pcon.h"

/* The big 3 */
#include "routing.h"
#include "vnet.h"
#include "dpg.h"


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
		fprintf(stderr, "getaddrinfo: %s:%s : %d %s\n",
				name, port,
				r, gai_strerror(r));
		return -1;
	}

	struct addrinfo *ail = *ai;
	int sock = socket(ail->ai_family,
			ail->ai_socktype, ail->ai_protocol);
	if (sock < 0) {
		WARN("socket");
		return -2;
	}

	if (bind(sock, ail->ai_addr, ail->ai_addrlen) < 0) {
		WARN("bind");
		return -3;
	}

	if (listen(sock, 0xF) == -1) {
		WARN("failed to listen for new peers");
		return -4;
	}

	*fd = sock;
	return 0;
}

static int peer_listener_get_peer(int listen_fd, struct sockaddr_in *addr,
		socklen_t *addrlen)
{
	/* wait for new connections */
	*addrlen = sizeof(struct sockaddr_in);
	DEBUG("peer_listener: waiting for peer");
	int peer_fd = accept(listen_fd,
			(struct sockaddr *)addr, addrlen);
	DEBUG("peer_listener: got peer");

	if (peer_fd == -1) {
		WARN("failure to accept new peer");
		return -1;
	}

	return peer_fd;
}

static int peer_listener(int fd, dpg_t *dpg, routing_t *rd, vnet_t *vn, pcon_t *pc)
{

	for(;;) {
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int con_fd = peer_listener_get_peer(fd, &addr, &addrlen);

		if (con_fd < 0) {
			DIE("peer_listener_get_peer failed");
		}

		/* start peer listener. req: peer_collection fully processed */
		int ret = dp_create_incoming(dpg, rd, vn, pc, con_fd, &addr);
		if (ret) {
			DIE("dpeer_init_incomming failed");
		}
	}
	return 0;
}

/* data for each raw read thread */
struct vnet_reader_arg {
	vnet_t *vnet;
	routing_t *rd;
	dpg_t *dpg;
};

#define DATA_MAX_LEN UINT16_MAX
static void *vnet_reader_th(void *arg)
{
	struct vnet_reader_arg *vra = arg;
	void *data = malloc(DATA_MAX_LEN);
	DEBUG("spawned: vnet_reader_th");
	for(;;) {
		size_t pkt_len = DATA_MAX_LEN;
		int r = vnet_recv(vra->vnet, data,
				&pkt_len);
		if (r < 0) {
			WARN("vnet_recv: %s", strerror(r));
			return NULL;
		}

		struct ether_header *eh = data;
		ether_addr_t dst_mac;
		memcpy(dst_mac.addr, eh->ether_dhost, ETH_ALEN);

		struct rt_hosts *hosts;
		ether_addr_t mac = vnet_get_mac(vra->vnet);
		r = rt_dhosts_to_host(vra->rd,
				mac, dst_mac, &hosts);
		if (r < 0) {
			WARN("rt_dhosts_to_host %s", strerror(r));
			return NULL;
		}

		struct rt_hosts *nhost = hosts;
		while (nhost) {
			ssize_t l = dp_send_data(dp_from_ip_host(nhost->addr),
					data, pkt_len);
			if (l < 0) {
				WARN("%s", strerror(l));
				return NULL;
			}
			nhost = nhost->next;
		}

		rt_hosts_free(vra->rd, hosts);
	}
	return vra;
}


static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"\n"
		"options:\n"
		"	-v		verbose/debug.\n"
		"	-i <tap name>	specify tap interface name.\n"
		"	-l <port>	listen port to bind to.\n"
		"	-e <host>	the external host ip/name to report.\n"
		"	-E <port>	the external port to report.\n"
		"	-r <host>	specify a peer to connect to (host)\n"
		"	-R <port>	specify a peer to connect to (port)\n"
		"	-Q <key>        encrypt trafic using aes with key.\n"
		"			each host must have the same key "
								"specified\n"
		"\n"
		"			if a host is specified without a\n"
		"			port, the default port (9000) or\n"
		"			the previous specified port of\n"
		"			that particular type is used\n"
		, name);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	char *tap_if = "tap5";
	char *ex_host = NULL;
	char *ex_port = DEFAULT_PORT_STR;
	char *peer_host = NULL;
	char *peer_port = DEFAULT_PORT_STR;
	char *listen_port = DEFAULT_PORT_STR;
	char *enc_key = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "vQ:i:e:E:r:R:l:h")) != -1) {
		switch (opt) {
		case 'v':
			debug++;
			break;
		case 'i':
			tap_if = optarg;
			DEBUG("tapif = %s", tap_if);
			break;
		case 'e':
			ex_host = optarg;
			DEBUG("ex_host = %s", ex_host);
			break;
		case 'E':
			ex_port = optarg;
			DEBUG("ex_port = %s", ex_port);
			break;
		case 'r':
			peer_host = optarg;
			DEBUG("peer_host = %s", peer_host);
			break;
		case 'R':
			peer_port = optarg;
			DEBUG("peer_port = %s", peer_port);
			break;
		case 'l':
			listen_port = optarg;
			DEBUG("listen_port = %s", listen_port);
			if (!strcmp(ex_port, DEFAULT_PORT_STR)) {
				ex_port = optarg;
				DEBUG("ex_port = %s", ex_port);
			}

			if (!strcmp(peer_port, DEFAULT_PORT_STR)) {
				peer_port = optarg;
				DEBUG("peer_port = %s", peer_port);
			}
			break;
		case 'Q':
			enc_key = optarg;
			DEBUG("enc_key = %s", enc_key);
			break;
		default:
			usage(argc?argv[0]:"L2O3");
			break;
		}
	}

	if (!ex_host) {
		fprintf(stderr, "arguments: at least ex_host (-e <host>)"
				" must be specified\n");
		usage(argc?argv[0]:"L2O3");
	}

	/* Initializes vnet, dpg, and routing.
	 * Spawns net listener and initial peer threads.
	 * Listens for new peers.
	 */
	vnet_t vnet;
	dpg_t dpg;
	routing_t rd;
	pcon_t pc;

	int ret = vnet_init(&vnet, tap_if);
	if(ret < 0) {
		WARN("vnet_init failed");
	}

	ret = dpg_init(&dpg, ex_host, ex_port);
	if(ret < 0) {
		DIE("dpg_init failed.");
	}

	struct ipv4_host ip_host = {
		.mac = vnet_get_mac(&vnet),
		.in = DPG_LADDR(&dpg)
	};

	ret = rt_init(&rd);
	if(ret < 0) {
		DIE("rd_init failed.");
	}

	ret = rt_lhost_add(&rd, &ip_host);
	if (ret < 0) {
		DIE("rd_dhost_add failed.");
	}

	ret = pcon_init(&pc);
	if (ret < 0) {
		DIE("peer connection limiter init failed.");
	}

	/* vnet listener spawn */
	if (vnet.fd != -1) {
		struct vnet_reader_arg vra = {
			.dpg = &dpg,
			.rd = &rd,
			.vnet = &vnet
		};

		pthread_t vnet_th;
		ret = pthread_create(&vnet_th, NULL, vnet_reader_th, &vra);
		if (ret) {
			DIE("pthread_create vnet_th failed.");
		}

		ret = pthread_detach(vnet_th);
		if (ret) {
			WARN("pthread_detach vnet_th failed.");
		}
	}

	/* inital dpeer spawn */
	if (peer_host && peer_port) {
		DEBUG("creating initial peer with %s : %s", peer_host, peer_port);
		ret = dp_create_initial(&dpg, &rd, &vnet, &pc, peer_host, peer_port);
		if (ret < 0) {
			WARN("initial dp init failed.");
		}
	}

	int fd;
	struct addrinfo *ai;
	if (peer_listener_bind(NULL, listen_port, &fd, &ai)) {
		DIE("peer_listener_bind failed.");
	}



	return peer_listener(fd, &dpg, &rd, &vnet, &pc);
}

