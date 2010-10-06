#include <sys/types.h>
#include <sys/socket.h> /* bind */

#include <netdb.h> /* getaddrinfo */

#include <stdio.h> /* fprintf, stderr */

#include <unistd.h> /* getopt */

#include <stdlib.h> /* realloc */
#include <string.h> /* memset */

#include <errno.h> /* errno */

/* packet (7) */
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

/* netdevice (7) */
#include <sys/ioctl.h>
#include <net/if.h>

#include <pthread.h>

#define DEFAULT_PORT_STR "9004"

/* Given to each thing writing to the raw net socket */
struct raw_net_write {
	int sock;
	pthread_mutex_t lock;
};

/* data for each peer thread.
 * one created for each peer.*/
struct peer_arg {
	char *name;
	char *port;

	struct addrinfo *ai;

	int con;
	pthread_t pth;
	pthread_mutex_t wrlock;	
	
	struct raw_net_write raw;
};

struct peer_collection {
	size_t pct;
	struct peer_arg **pd;
};

/* data for each raw read thread */
struct raw_net_read {
	char *l_if;
	struct peer_collection *peers;

	int sock;
};


/* data for each peer_listener thread.
 *  in practice, we have only one */
struct peer_listen_arg {
	char *name;
	char *port;
	struct peer_collection *peers;

	struct addrinfo *ai;

	int sock;
};

/* Packet queueing */
struct packet {
	struct sockaddr_ll addr;
	void *data;
};

struct packet_node {
	struct packet_node *next;
	struct packet *packet;
};

struct packet_queue {
	struct packet_node *head;
	struct packet_node *tail;
	struct packet_node *hold;
};


int packet_enqueue(struct packet_queue *pq, struct packet *p)
{

}

struct packet *packet_dequeue(struct packet_queue *pq)
{

}

#define DIE(...) do {                                   \
	fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__);                   \
	fputc('\n', stderr);                            \
	exit(EXIT_FAILURE);                             \
} while (0)

static struct peer_collection *peers_mk(void)
{
	struct peer_collection *p = malloc(sizeof(*p));
	if (!p) {
		DIE("no mem for %s", __func__);
	}

	memset(p, 0, sizeof(p));
	return p;
}

struct peer_arg *peer_outgoing_mk(char *name, char *port)
{
	struct peer_arg *pa = malloc(sizeof(*pa));
	if (pa) {
		memset(pa, 0, sizeof(*pa));
		pa->name = name;
		pa->port = port;
	}
	return pa;
}

struct peer_arg *peer_incomming_mk(size_t addrlen)
{
	struct peer_arg *pa = malloc(sizeof(*pa));
	if (pa) {
		memset(pa, 0, sizeof(*pa));
		pa->ai->ai_addrlen = addrlen;
		pa->ai->ai_addr = malloc(addrlen);
		if (!pa->ai->ai_addr) {
			free(pa);
			return 0;
		}
	}
	return pa;
}

static int peers_add(struct peer_collection *pc, struct peer_arg *pa)
{
	size_t loc = pc->pct;
	pc->pct ++;
	pc->pd = realloc(pc->pd, sizeof(*pc->pd) * pc->pct);
	if (!(pc->pd)) {
		return errno;
	}

	pc->pd[loc] = pa;
	return 0;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s <port> <local interface>\n"
		"       %s <remote host> <remote port> <local interface>\n"
		, name, name);
	exit(EXIT_FAILURE);
}

void *th_peer_reader(void *arg)
{
	struct peer_arg *pd = arg;

	/* init */

	/* check for data on the assigned queue input queue */
	/* also check for incomming data */

	return pd;
}

void *th_peer_listen(void *arg)
{
	struct peer_listen_arg *pl = arg;

	/** init **/

	/* get data to bind */
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	int r = getaddrinfo(pl->name,
			pl->port, &hints,
			&pl->ai);
	if (r) {
		fprintf(stderr, "whoops: %s: %d %s\n",
				pl->name,
				r, gai_strerror(r));
	}

	int sock = socket(pl->ai->ai_family,
			pl->ai->ai_socktype, pl->ai->ai_protocol);
	if (sock < 0) {
		DIE("socket: %s", strerror(sock));
	}

	if (bind(sock, pl->ai->ai_addr, pl->ai->ai_addrlen) < 0) {
		DIE("bind: %s", strerror(errno));
	}

	for(;;) {
		struct peer_arg *peer = peer_incomming_mk(
				sizeof(struct sockaddr_storage));

		/* wait for new connections */
		peer->con = accept(sock, peer->ai->ai_addr, &peer->ai->ai_addrlen);

		/* XXX: populate peer data
		 * specifically, peer->ai (addrinfo) needs filling */
		if (peers_add(pl->peers, peer))
			DIE("In a flaming ball of fire.");

		/* spawn peer thread */
		int r = pthread_create(&peer->pth, NULL, th_peer_reader, peer);
		if (r) {
			DIE("pthread_create: %s", strerror(r));
		}
	}
}

void *th_raw_net_reader(void *arg)
{
	struct raw_net_read *rn = arg;

	return rn;
}


#if 0
static void forward_packet(struct peer_collection *peers, packet)
{
	/* TODO: decide what to do with the packet */
}

static void transmit_packet(struct peer_arg *peer, packet)
{
	write(peer->con, htons(0xABCD));
	write(peer->con, htons(length(packet));
	write(peer->con, data(packet));
}
#endif

# define CMBSTR3(s1, i, s2) CMBSTR3_(s1,i,s2)
# define CMBSTR3_(str1, ins, str2) str1 #ins str2
int raw_create(struct raw_net_read *rn)
{
	/** using PACKET sockets, packet(7) **/
	/* reception with packet sockets will be fine,
	 * documentation on sending is sketchy. especially
	 * what the contents of sll_addr should be
	 */

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		DIE("socket(PACKET): %s", strerror(sock));
	}

	/* SIOCGIFINDEX
	 * see netdevice(7) */
	struct ifreq ifreq;

	/* overflow bad */
	strncpy(ifreq.ifr_name, rn->l_if, IFNAMSIZ);
	int ret = ioctl(sock, SIOCGIFINDEX, &ifreq);
	if (ret < 0) {
		DIE(CMBSTR3("SIOCGIFINDEX %",IFNAMSIZ,"s: %s"),
			ifreq.ifr_name, strerror(ret));
	}

	int ifindex = ifreq.ifr_ifindex;

	struct sockaddr_ll sll_bind;

	/*  When you send packets it is enough to specify sll_family, sll_addr,
	 *  sll_halen, sll_ifindex. The other fields should be 0. sll_hatype
	 *  and sll_pkttype are set on received packets for your
	 *  information. For bind only sll_protocol and sll_ifindex are used.
	 */

	/* All needed for bind */
	sll_bind.sll_family = AF_PACKET;
	sll_bind.sll_ifindex = ifindex;
	sll_bind.sll_protocol = /*???*/0;

	ret = bind(sock, (struct sockaddr *) &sll_bind, sizeof(sll_bind));
	if (ret < 0) {
		DIE(CMBSTR3("bind %",IFNAMSIZ,"s: %s"),
			ifreq.ifr_name, strerror(ret));
	}

	rn->sock = sock;

	return 0;
#if 0
	/* transmition */
	memset(&sll_send, 0, sizeof(sll_send));
	sll_send.sll_family = AF_PACKET;
	sll_send.sll_addr = /*??? */0;
	sll_send.sll_halen = /*??? */0;
	sll_send.sll_ifindex = ifindex;
#endif
}

int main(int argc, char **argv)
{
	struct peer_collection *peers = peers_mk();
	struct peer_listen_arg ld_ = { .peers = peers }, *ld = &ld_;
	struct raw_net_read rn_ = { .peers = peers }, *rn = &rn_;

	if (argc == 3) {
		/* listener */
		ld->name = 0;
		ld->port = argv[1];
		rn->l_if = argv[2];
	} else if (argc == 4) {
		/* connector */
		ld->name = 0;
		ld->port = DEFAULT_PORT_STR;
		rn->l_if = argv[3];

		char *rname = argv[1];
		char *rport = argv[2];
		struct peer_arg *peer = peer_outgoing_mk(rname, rport);
		if (!peer)
			DIE("WTH");
		if (peers_add(peers, peer))
			DIE("Oh god, my eyes.");
	} else {
		usage((argc>0)?argv[0]:"L203");
	}

	fprintf(stderr, "we have %zu peers:\n", peers->pct);
	size_t i;
	for (i = 0; i < peers->pct; i++) {
		fprintf(stderr, " name: %s:%s\n", peers->pd[i]->name,
				peers->pd[i]->port);
	}

	/* start initial peer processes */

	/* seed-peer data population */
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	for (i = 0; i < peers->pct; i++) {
		int r = getaddrinfo(peers->pd[i]->name,
				peers->pd[i]->port, &hints,
				&peers->pd[i]->ai);
		if (r) {
			fprintf(stderr, "whoops: %s: %d %s\n",
					peers->pd[i]->name,
					r, gai_strerror(r));
		}
	}

	/* start peer listener. req: peer_collection fully processed */
	pthread_t listen_pth;
	int ret = pthread_create(&listen_pth, NULL, th_peer_listen, ld);

	/* start raw_net thread */
	pthread_t rawnet_pth;
	ret = pthread_create(&rawnet_pth, NULL, th_raw_net_reader, rn);

	/* FIXME: ??? */

	return 0;
}

#if 0
int complex_parse_args(int argc, char **argv)
{
	char *listen_port;
	struct peer_arg *peers = 0;
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
