
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

#include "peer_packet.h"

struct packet {
	size_t len;
	char data[2048];
};

struct net_data {
	char *ifname;
	int net_sock;
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

static int net_send_packet(struct net_data *nd,
		void *packet, size_t size)
{
	ssize_t w = write(nd->net_sock, packet, size);
	if (w != size) {
		WARN("packet write %zd %s", w, strerror(errno));
		return -1;
	}
	return 0;
}

/* sockaddr_ll is populated by a call to this function */
static int net_recv_packet(struct net_data *nd, void *buf, size_t *nbyte)
{
	ssize_t len = read(nd->net_sock, buf, *nbyte);
	if (len < 0) {
		WARN("packet read died %zd, %s",len, strerror(errno));
		return -1;
	}
	*nbyte = len;
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

#if 0
static int peer_recv(int peer_fd)
{
	uint16_t header[2];
	ssize_t r = recv(peer_fd, header, sizeof(header), MSG_WAITALL);
	switch(header[0]) {
		/* packet type */

	}
}
#endif

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
		/* XXX: on client & server ctrl-c, this fires */
		WARN("Packet not read %s", strerror(errno));
		return -errno;
	} else if (r == 0) {
		WARN("client disconnected.");
		return 1;
	}

	size_t packet_length = ntohs(head_buf[1]);
	if (*nbyte < packet_length) {
		WARN("Buffer size (%zu) smaller than packet (%zu)",
				packet_length, *nbyte);
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

		return -ENOMEM;
	}

	/*Recieve data into buffer*/
	r = recv(peer_sock, buf, packet_length, MSG_WAITALL);
	if (r == -1) {
		WARN("recv faild %s", strerror(errno));
		return -errno;
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

static int net_init(struct net_data *nd, char *ifname)
{
	int fd, err;
	struct ifreq ifr;
	if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		WARN("open");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if ( (err = ioctl(fd, TUNSETIFF, &ifr)) < 0 ) {
		WARN("TUNSETIFF: %s", strerror(errno));
		close(fd);
		return err;
	}

	nd->ifname = ifname;
	nd->net_sock = fd;

	return 0;
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


	if (peer_listener_bind(pl)) {
		DIE("peer_listener_bind failed.");
	}

	for(;;) {
		struct peer_reader_arg *pa = peer_listener_get_peer(pl);

		if (!pa) {
			DIE("peer_listener_get_peer failed");
		}

		/* start peer listener. req: peer_collection fully processed */
		pthread_t peer_pth, net_pth;
		int ret = pthread_create(&peer_pth, NULL, th_peer_reader, pa);
		if (ret) {
			DIE("pthread_create th_peer_reader failed");
		}

		/* start raw_net thread */
		nr->peer_sock = pa->peer_sock;
		ret = pthread_create(&net_pth, NULL, th_net_reader, nr);
		if (ret) {
			DIE("pthread_create th_net_reader failed");
		}

		pthread_join(peer_pth, NULL);
		WARN("pthread_join peer_pth");
		pthread_join(net_pth, NULL);
	}
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

