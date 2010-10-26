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

/* packet (7) */
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

/* netdevice (7) */
#include <sys/ioctl.h>
#include <net/if.h>

/* filtering */
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/filter.h>

#include <pthread.h>

#define DEFAULT_PORT_STR "9004"

/* tcpdump -d \( not ip \) or \( ip net 192.168.0.0/24 \)
 (000) ldh      [12]
 (001) jeq      #0x800           jt 2	jf 9
 (002) ld       [26]
 (003) and      #0xffffff00
 (004) jeq      #0xc0a80000      jt 9	jf 5
 (005) ld       [30]
 (006) and      #0xffffff00
 (007) jeq      #0xc0a80000      jt 9	jf 8
 (008) ret      #0
 (009) ret      #65535
 */

/* __SUBNET_MASK__ and __SUBNET_VAL__ need to be replaced with actual values
 * (at runtime)
 * Note: BPF_LD converts things to host byte order, so SUBNET_* need to be
 * in host byte order aswell.
 */
#define FILT_IP_CHECK 4
#define FILT_SUB_CHECK 3
static struct sock_filter net_filter[] = {
	/* 0: Load h_proto in ethernet header */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsetof(struct ethhdr, h_proto)),

	/* 1: Check for IP packets. T = next, F = done succ. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0/*2-1-1*/, 3/*5-1-1*/),

	/* 2: load ip src */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			ETH_HLEN + offsetof(struct iphdr, saddr)),

	/* 3: And it to compare for subnet */
	BPF_STMT(BPF_ALU | BPF_AND, 0xdeadbeef /*__SUBNET_MASK__*/ ),

	/* 4: is ipsrc == the address assigned to the fake virtual? */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			0xdeadbeef /*__SUBNET_VAL__*/, 0/*5-4-1*/, 1/*6-4-1*/),

	/* 5: accept entire packet */
	BPF_STMT(BPF_RET | BPF_K, -1),

	/* 6: reject packet */
	BPF_STMT(BPF_RET | BPF_K, 0)
};

static struct sock_fprog fcode = {
	.len = sizeof(net_filter) / sizeof(*net_filter),
	.filter = net_filter
};



struct packet {
	size_t len;
	char data[2048];
};

struct net_data {
	char *ifname;
	int net_sock;
	int ifindex;

	uint32_t net_sub;
	uint32_t net_sub_ip;
	uint32_t net_ip;
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

static int net_send_packet(struct net_data *nd,
		void *packet, size_t size)
{
	if (nd->ifindex != -1) {
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
	} else {
		ssize_t w = write(nd->net_sock, packet, size);
		if (w != size) {
			WARN("packet write %zd %s", w, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/* sockaddr_ll is populated by a call to this function */
static int net_recv_packet(struct net_data *nd, void *buf, size_t *nbyte)
{
	if (nd->ifindex != -1) {
		ssize_t r;
		struct sockaddr_ll sa;
		memset(&sa, 0, sizeof(sa));
		socklen_t sl = sizeof(sa);

		r = recvfrom(nd->net_sock, buf, *nbyte, 0,
				(struct sockaddr *)&sa, &sl);
		if (r < 0) {
			WARN("packet read died %zd, %s",r, strerror(errno));
			return -1;
		}
		*nbyte = r;
	} else {
		ssize_t len = read(nd->net_sock, buf, *nbyte);
		if (len < 0) {
			WARN("packet read died %zd, %s",len, strerror(errno));
			return -1;
		}
		*nbyte = len;
	}
	return 0;
}

static int peer_send_packet(int peer_sock, void *buf, size_t nbyte)
{
	short header[] = { htons(0xABCD), htons(nbyte) };
	ssize_t tmit_sz, pos = 0, rem_sz = sizeof(header);
	/* send header allowing for "issues" */
	do {
		tmit_sz = send(peer_sock, ((char*)header + pos), rem_sz, 0);
		if (tmit_sz < 0) {
			WARN("send header: %s", strerror(errno));
			return -1;
		}
		rem_sz -= tmit_sz;
		pos += tmit_sz;
	} while (rem_sz > 0);

	pos = 0; rem_sz = nbyte;
	do {
		tmit_sz = send(peer_sock, ((char*)buf) + pos, rem_sz, 0);
		if (tmit_sz < 0) {
			WARN("send data: %s", strerror(errno));
			return -1;
		}
		rem_sz -= tmit_sz;
		pos += tmit_sz;
	} while (rem_sz > 0);

	return 0;
}

static int peer_recv_packet(int peer_sock, void *buf, size_t *nbyte)
{
	if(*nbyte == 0){
		WARN("Buffer size problems");
		return -ENOMEM;
	}
	/*recieve header into head_buf, position 2 of head_buf contains length
	 of data being recieved  */
	uint16_t head_buf[2];
	ssize_t r = recv(peer_sock, head_buf, sizeof(head_buf), MSG_WAITALL);
	if(r == -1) {
		WARN("Packet not read %s", strerror(errno));
		return errno;
	}

	size_t packet_length = ntohs(head_buf[1]);
	if (*nbyte < packet_length) {
		/* Our buffer isn't big enough for all the data, but we still
		 * want to maintain sync with the remote host, so
		 * flush the current packet */
		size_t x;
		for(x = 0; x + *nbyte < packet_length; x += *nbyte) {
			r = recv(peer_sock, buf, *nbyte,
				MSG_WAITALL);
			if (r == -1) {
				/* XXX: can we do anything about this error? */
			}
		}
		r = recv(peer_sock, buf, packet_length - x,
				MSG_WAITALL);
		if (r == -1) {
			/* XXX: can we do anything about this error? */
		}

		WARN("Buffer size smaller than packet");
		return -ENOMEM;
	}

	/*Recieve data into buffer*/
	r = recv(peer_sock, buf, packet_length, MSG_WAITALL);
	if (r == -1) {
		WARN("recv faild %s", strerror(errno));
		return errno;
	}
	*nbyte = r;
	return 0;
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
		if (r) {
			WARN("Failed to recieve packet. %s", strerror(r));
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

/* Given a set pl->port, initializes the pl->sock (and pl->ai) */
static int peer_listener_bind(struct peer_listener_arg *pl)
{
	/* get data to bind */
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	/* FIXME: bound to IPv6 for now */
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

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

	if (listen(sock, 0xF) == -1) {
		WARN("failed to listen for new peers: %s", strerror(errno));
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

	if (peer->peer_sock == -1) {
		/* FIXME: deallocate peer */
		WARN("failure to accept new peer: %s", strerror(errno));
		return NULL;
	}

	/* XXX: populate peer data
	 * specifically, peer->ai (addrinfo) needs filling */

	return peer;
}

#ifdef DEBUG
static void print_fcode(struct sock_fprog *fcode)
{
	size_t i;
	for (i = 0; i < fcode->len; i++) {
		struct sock_filter *op = fcode->filter + i;
		printf("{ 0x%x, %d, %d, 0x%08x },\n",
				op->code, op->jt, op->jf, op->k);
	}
}
#endif

# define CMBSTR3(s1, i, s2) CMBSTR3_(s1,i,s2)
# define CMBSTR3_(str1, ins, str2) str1 #ins str2

static int net_init_tap(struct net_data *nd, char *ifname)
{
	int fd, err;
	struct ifreq ifr;
	if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return -1;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (*ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if ( (err = ioctl(fd, TUNSETIFF, &ifr)) < 0 ) {
		close(fd);
		return err;
	}

	nd->ifname = ifname;
	nd->ifindex = -1;
	nd->net_sock = fd;

	return 0;
}

static int net_init_bad(struct net_data *nd, char *ifname)
{
	WARN("using bad network initialization, kernel will never see packets");
	/** using PACKET sockets, packet(7) **/
	/* reception with packet sockets will be fine,
	 * documentation on sending is sketchy. especially
	 * what the contents of sll_addr should be
	 */

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		WARN("socket(AF_PACKET,SOCK_RAW, ...): %s", strerror(errno));
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
			ifreq.ifr_name, strerror(errno));
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
			ifreq.ifr_name, strerror(errno));
		close(sock);
		return ret;
	}

	nd->ifname = ifname;
	nd->ifindex = ifindex;
	nd->net_sock = sock;

	/* FILTER: completely optional if you don't mind your machine grinding
	 * to a halt due to an inane amount of traffic. Only warn on errors.
	 * */
	{
#ifdef DEBUG
		WARN("filter start");
		print_fcode(&fcode);
#endif

		/* obtain ip & netmask of named IF */
		int inet_sock = socket(AF_INET, SOCK_STREAM, 0);

		struct ifreq req;
		memset(&req, 0, sizeof(req));
		strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

		struct sockaddr_in *addr = (struct sockaddr_in *)&(req.ifr_addr);

		ret = ioctl(inet_sock, SIOCGIFADDR, &req);

		if (ret < 0) {
			if (errno == EADDRNOTAVAIL) {
				WARN(CMBSTR3("interface %", IFNAMSIZ,
					"s does not have an address"),
					req.ifr_name);
				return 1;
			} else {
				WARN("SIOCGIFADDR fail: %s", strerror(errno));
			}
			return 1;
		}

		nd->net_ip = ntohl(addr->sin_addr.s_addr);

		ret = ioctl(inet_sock, SIOCGIFNETMASK, &req);
		if (ret < 0) {
			WARN("SIOCGIFNETMASK fail: %s", strerror(errno));
			return 1;
		}
		nd->net_sub = ntohl(addr->sin_addr.s_addr);

		nd->net_sub_ip = nd->net_sub & nd->net_ip;

		net_filter[FILT_IP_CHECK].k = nd->net_sub_ip;
		net_filter[FILT_SUB_CHECK].k = nd->net_sub;

#ifdef DEBUG
		WARN("Populated:");
		print_fcode(&fcode);
#endif

		ret = setsockopt(nd->net_sock, SOL_SOCKET, SO_ATTACH_FILTER,
				&fcode, sizeof(fcode));

		if (ret < 0) {
			WARN("filter failed %s", strerror(errno));
			return 1;
		}
	}

	return 0;
}

static int net_init(struct net_data *nd, char *ifname)
{
	if (!strncmp(ifname, "tun", 3)) {
		return net_init_tap(nd, ifname);
	} else {
		return net_init_bad(nd, ifname);
	}
}

static int main_listener(char *ifname, char *name, char *port)
{
	struct net_data nd;
	int nret;
	nret = net_init(&nd, ifname);
	if(nret < 0) {
		DIE("net init failed.");
	} else if (nret == 1) {
		WARN("not able to filter \"virtual\" net.");
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
		DIE("peer_listener_bind failed.");
	}

	for(;;) {
		struct peer_reader_arg *pa = peer_listener_get_peer(pl);

		if (pa == NULL) {
			return -1;
		}

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

