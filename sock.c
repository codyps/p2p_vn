#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> /* getaddrinfo */

#include <stdio.h> /* fprintf, stderr */

#include <unistd.h> /* getopt */

#include <stdlib.h> /* realloc */
#include <string.h> /* memset */

#define DEFAULT_PORT_STR "9004"

struct peer_data {
	char *name;
	char *port;
	struct addrinfo *res;
};

struct peer_array {
	size_t pct;
	struct peer_data *pd;
};


struct listener_data {
	char *l_if;
	char *l_port;
};

#define DIE(...) do {                                   \
	fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__);                   \
	fputc('\n', stderr);                            \
	exit(EXIT_FAILURE);                             \
} while (0)

static struct peer_array *peer_array_mk(void)
{
	struct peer_array *p = malloc(sizeof(*p));
	if (!p) {
		DIE("no mem for peer_array_mk");
	}

	memset(p, 0, sizeof(p));
	return p;
}

static void peer_add(struct peer_array *pa, char *name, char *port)
{
	pa->pct ++;
	pa->pd = realloc(pa->pd, sizeof(*pa->pd) * pa->pct);
	memset(pa->pd + pa->pct - 1, 0, sizeof(*pa->pd));
	pa->pd[pa->pct - 1].name = name;
	pa->pd[pa->pct - 1].port = port;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s <port> <local interface>\n"
		"       %s <remote host> <remote port> <local interface>\n"
		, name, name);
	exit(EXIT_FAILURE);
}

#if 0
static void forward_packet(struct peer_list *peers, packet)
{
	/* TODO: decide what to do with the packet */
}

static void transmit_packet(struct peer_data *peer, packet)
{
	write(peer->con, htons(0xABCD));
	write(peer->con, htons(length(packet));
	write(peer->con, data(packet));
}
#endif

int main(int argc, char **argv)
{
	struct listener_data ld_, *ld = &ld_;
	struct peer_array *peers = peer_array_mk();

	if (argc == 3) {
		/* listener */

		ld->l_port = argv[1];
		ld->l_if = argv[2];
	} else if (argc == 4) {
		/* connector */

		ld->l_port = DEFAULT_PORT_STR;
		ld->l_if = argv[3];

		char *rname = argv[1];
		char *rport = argv[2];
		peer_add(peers,rname,rport);
	} else {
		usage((argc>0)?argv[0]:"L203");
	}

	fprintf(stderr, "we have %zu peers:\n", peers->pct);
	size_t i;
	for (i = 0; i < peers->pct; i++) {
		fprintf(stderr, " name: %s:%s\n", peers->pd[i].name,
				peers->pd[i].port);
	}

	/* TODO: bind to peer port */

	/* TODO: bind to raw listen if */

#if 0
	/** using PACKET sockets **/
	int rlsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (rlsock < 0) {
		DIE("bad sock");
	}

	int ifindex = ???;

	struct sockaddr_ll sll;

	/*  When you send packets it is enough to specify sll_family, sll_addr,
	 *  sll_halen, sll_ifindex. The other fields should be 0. sll_hatype
	 *  and sll_pkttype are set on received packets for your
	 *  information. For bind only sll_protocol and sll_ifindex are used.
	 */

	/* All needed for bind */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = ???;


	bind

#endif

#if 0
	/** using IP_NET RAW sockets **/
	int rlsock = socket(AF_INET, SOCK_RAW, 0);
#endif

#if 0
	/** using libpcap **/
	char errbuf[PCAP_ERRBUF_SIZE] = '\0';
	pcap_t *rlcap = pcap_create(ld->l_if, errbuf);
	if (!rlcap) {
		/* error */
		fprintf(stderr, "error: %s", errbuf);
		exit(EXIT_FAILURE);
	}

	int ret = pcap_set_promisc(rlcap, 1);
	if (ret) {
		pcap_perror(rlcap, "error: ");
		exit(EXIT_FAILURE);
	}

	ret = pcap_set_buffer_size(rlcap, 1500 * 200);
	if (ret) {
		pcap_perror(rlcap, 0);
		exit(EXIT_FAILURE);
	}

	ret = pcap_activate(rlcap);
	if (ret) {
		pcap_perror(rlcap, "error: ");
		exit(EXIT_FAILURE);
	}

#endif

	/* seed-peer data population */
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	for (i = 0; i < peers->pct; i++) {
		int r = getaddrinfo(peers->pd[i].name,
				peers->pd[i].port, &hints,
				&peers->pd[i].res);
		if (r) {
			fprintf(stderr, "whoops: %s: %d %s\n",
					peers->pd[i].name,
					r, gai_strerror(r));
		}
	}

	/* TODO: connect to peers */

	/* TODO: main loop { */

	/* TODO: deal with new incomming conections */
	/* TODO: form outgoing connections */
	/* TODO: deal with data from connected peers */
	/* TODO: request data from connected peers */
	/* TODO: send data to peers */

	/* } */

	return 0;
}

#if 0
int complex_parse_args(int argc, char **argv)
{
	char *listen_port;
	struct peer_data *peers = 0;
	size_t peer_ct = 0;
	int opt;
	while ((opt = getopt(argc, argv, "l:P:p:")) != -1) {
		switch (opt) {
		case 'p':
			if (peer_ct && !peers[peer_ct - 1].port)
				peers[peer_ct - 1].port = DEFAULT_PORT_STR;

			peer_ct ++;
			peers = realloc(peers, sizeof(*peers) * peer_ct);
			memset(peers + peer_ct - 1, 0, sizeof(*peers));
			peers[peer_ct - 1].name = optarg;
			break;


		case 'P':
			peers[peer_ct - 1].port = optarg;
			break;

		case 'l':
			listen_port = optarg;
			break;

		default: /* '?' */
			fprintf(stderr, "usage: %s [-l listen_port]"
					" [-p peer [-P peer_port]]... \n",
					argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}
#endif
