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

struct packet {
	size_t len;
	char data[2048];
};

struct net_data {
	char *ifname;
	int net_sock;
	int ifindex;
};

/* data for each peer thread.
 * one created for each peer.*/
struct peer_reader_arg {
	char *name;
	char *port;

	struct addrinfo *ai;

	int peer_sock;

	/* output */
	struct net_data *net_data;
};

/* data for each raw read thread */
struct net_reader_arg {
	struct net_data *net_data;

	/* output */
	int peer_sock;
};


/* data for each peer_listener thread.
 *  in practice, we have only one */
struct peer_listener_arg {
	char *name;
	char *port;
	struct addrinfo *ai;

	int listen_sock;

	struct net_data *net_data;
};

#define WARN(...) do {                                  \
	fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__);                   \
	fputc('\n', stderr);                            \
} while(0);

#define DIE(...) do {       \
	WARN(__VA_ARGS__);  \
	exit(EXIT_FAILURE); \
} while (0)


struct peer_reader_arg *peer_outgoing_mk(struct net_data *nd, char *name,
		char *port)
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

struct peer_reader_arg *peer_incomming_mk(struct net_data *nd, size_t addrlen)
{
	struct peer_reader_arg *pa = malloc(sizeof(*pa));
	if (pa) {
		memset(pa, 0, sizeof(*pa));
		pa->ai->ai_addrlen = addrlen;
		pa->ai->ai_addr = malloc(addrlen);
		pa->net_data = nd;
		if (!pa->ai->ai_addr) {
			free(pa);
			return 0;
		}
	}
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

static int net_write_link(struct net_data *nd,
		uint8_t *packet, size_t size)
{
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_ifindex = nd->ifindex,
		.sll_protocol = htons(ETH_P_ALL)
	};

	ssize_t c = sendto(nd->net_sock, packet, size, 0,
			(struct sockaddr *)&sa,
			sizeof(sa));

	if (c != size) {
		WARN("packet write died %zd.", c);
		return -1;
	}

	return 0;
}

static int net_read_link(struct net_data *nd, uint8_t *buf, size_t len)
{

}

static void *th_net_reader(void *arg)
{
	struct net_reader_arg *rn = arg;

	return rn;
}

static void *th_peer_reader(void *arg)
{
	struct peer_reader_arg *pd = arg;

	/* init */

	/* check for data on the assigned queue input queue */
	/* also check for incomming data */

	return pd;
}

/* Given a set pl->port, initializes the pl->sock (and pl->ai) */
static int peer_listener_bind(struct peer_listener_arg *pl)
{
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
		WARN("socket: %s", strerror(errno));
		return errno;
	}

	if (bind(sock, pl->ai->ai_addr, pl->ai->ai_addrlen) < 0) {
		WARN("bind: %s", strerror(errno));
		return errno;
	}

	pl->listen_sock = sock;
	return 0;
}


struct peer_reader_arg *peer_listener_get_peer(struct peer_listener_arg *pl)
{
	struct peer_reader_arg *peer = peer_incomming_mk(pl->net_data,
		sizeof(struct sockaddr_storage));

	if (!peer) {
		WARN("blah");
		return 0;
	}

	/* wait for new connections */
	peer->peer_sock = accept(pl->listen_sock,
			peer->ai->ai_addr, &peer->ai->ai_addrlen);

	/* XXX: populate peer data
	 * specifically, peer->ai (addrinfo) needs filling */

	return peer;
}

# define CMBSTR3(s1, i, s2) CMBSTR3_(s1,i,s2)
# define CMBSTR3_(str1, ins, str2) str1 #ins str2
int net_init(struct net_data *nd, char *ifname)
{
	/** using PACKET sockets, packet(7) **/
	/* reception with packet sockets will be fine,
	 * documentation on sending is sketchy. especially
	 * what the contents of sll_addr should be
	 */

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		WARN("socket(PACKET): %s", strerror(sock));
		return sock;
	}

	/* SIOCGIFINDEX
	 * see netdevice(7) */
	struct ifreq ifreq;

	/* overflow bad */
	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
	int ret = ioctl(sock, SIOCGIFINDEX, &ifreq);
	if (ret < 0) {
		WARN(CMBSTR3("SIOCGIFINDEX %",IFNAMSIZ,"s: %s"),
			ifreq.ifr_name, strerror(ret));
		close(sock);
		return ret;
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
	sll_bind.sll_protocol = htons(ETH_P_ALL);

	ret = bind(sock, (struct sockaddr *) &sll_bind, sizeof(sll_bind));
	if (ret < 0) {
		WARN(CMBSTR3("bind %",IFNAMSIZ,"s: %s"),
			ifreq.ifr_name, strerror(ret));
		close(sock);
		return ret;
	}

	nd->ifname = ifname;
	nd->ifindex = ifindex;
	nd->net_sock = sock;

	return 0;
}


int main_listener(char *ifname, char *name, char *port)
{
	struct net_data nd;
	if (net_init(&nd, ifname)) {
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


	if (peer_listener_bind(pl)) {
		DIE("OH GOD");
	}

	for(;;) {
		struct peer_reader_arg *pa = peer_listener_get_peer(pl);

		/* start peer listener. req: peer_collection fully processed */
		pthread_t peer_pth, net_pth;
		int ret = pthread_create(&peer_pth, NULL, th_peer_reader, pa);
		if (ret) {
			DIE("meh");
		}

		/* start raw_net thread */
		nr->peer_sock = pa->peer_sock;
		ret = pthread_create(&net_pth, NULL, th_net_reader, nr);
		if (ret) {
			DIE("hello");
		}

		pthread_join(net_pth, NULL);
		pthread_join(peer_pth, NULL);
	}
}

int main_connector(char *ifname, char *host, char *port)
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
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	int r = getaddrinfo(peer->name,
			peer->port, &hints,
			&peer->ai);
	if (r) {
		WARN("getaddrinfo: %s: %d %s",
				peer->name,
				r, gai_strerror(r));
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
		return main_listener(argv[2], 0, argv[1]);
	} else if (argc == 4) {
		/* connector <ifname> <rhost> <rport> */
		return main_connector(argv[3], argv[1], argv[2]);
	} else {
		usage((argc>0)?argv[0]:"L203");
	}
	return 0;
}

