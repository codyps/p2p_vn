#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "debug.h"
#include "peer_proto.h"

#include "dpeer.h"
#include "poll.h"

static int dp_recv_packet(struct direct_peer *dp)
{
	struct pkt_header header;
	ssize_t r = recv(dp->con_fd, header, PL_HEADER, MSG_WAITALL);
	if(r == -1) {
		/* XXX: on client & server ctrl-c, this fires */
		DP_WARN(dp, "recv packet: %s", strerror(errno));
		return -errno;
	} else if (r < PL_HEADER) {
		DP_WARN(dp, "client disconnected.");
		return 1;
	}

	uint16_t pkt_length = ntohs(header.type);
	uint16_t pkt_type   = ntohs(header.length);

	switch (pkt_type) {
	case PT_DATA: {
		char *pkt = malloc(pkt_length);
		ssize_t r = recv(dp->con_fd, pkt, pkt_length, MSG_WAITALL);
		if (r == -1) {
		break;
	}

	case PT_LINK: {
		/* subtract header from rest of data, find
	 	   out how many neighbors there are
		   and sort information so we can receive. */
		char *pkt = malloc(pkt_length);
		ssize_t data= recv(dp->con_fd, pkt, pkt_length, MSG_WAITALL);
		/* size of total neighbors? not sure about this */
		int neighbors= r - entire;
		break;
	}
	case PT_JOIN_PART:
		switch (pkt_length) {
		case PL_JOIN:
			break;
		case PL_PART:
			break;
		default:
			goto error_recv_flush;
		}
		break;

	case PT_QUIT:
		break;

	case PT_PROBE_REQ:
		/* someone is requesting a probe response */
		break;

	case PT_PROBE_RESP:
		/* someone responded to our probe */
		break;

	default:
error_recv_flush:
		/* unknown, read entire packet to maintain alignment. */

	}

	return 0;
}

struct dp_init_arg {
	dp_t *dp;
	char *host;
	char *port;
};

struct dp_link_arg{
	dp_t *dp;
	ether_addr_t mac;
	__be32 inet_addr;
	__be16 inet_port;
};

struct dp_incoming_arg {
	dp_t *dp;
	int fd;
};

int dp_init_initial(dp_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		char *host, char *port)
{
	dp->rd = rd;
	dp->dpg = dpg;
	dp->vnet = vnet;
	dp->wlock = PTHREAD_MUTEX_INITIALIZER;
	
	struct dp_init_arg init_th =
		{.dp = dp, .host=host, .port=port};


	/* TODO: spawn dp_init_th and detach */
	return 0;
}

void *dp_link_th(void *dp_v) 
{
	dp_t dp = *dp_v;
	
	struct pkt_header header;
	ssize_t r = recv(dp->con_fd, header, PL_HEADER, MSG_WAITALL);
	if(r == -1) {
		/* XXX: on client & server ctrl-c, this fires */
		DP_WARN(dp, "recv packet: %s", strerror(errno));
		return -errno;
	} else if (r < PL_HEADER) {
		DP_WARN(dp, "client disconnected.");
		return 1;
	}

	uint16_t pkt_length = ntohs(header.type);
	uint16_t pkt_type   = ntohs(header.length);
	if(pkt_type == PT_JOIN_PART && pkt_length == PL_JOIN) {
		char *pkt = malloc(pkt_length);
		ssize_t r = recv(dp->con_fd, pkt, pkt_length, MSG_WAITALL);
		int x;
		for(x = 0; x < 6; x++) {
			dp->remote_mac[x] = pkt[x + 6];
		}
	}
	
	//if not join packet close, free stuff.
	//dp_recvPcket (look up) or something. in dpeer. recv(dp->con_fd, header, PL_HEADER, MSG_WAITALL);

	return -1;
}

int dp_init_linkstate(dp_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		ether_addr_t mac, __be32 inet_addr, __be16 inet_port)
{
	dp->routing = rd;
	dp->dpg = dpg;
	dp->vnet = vnet;

	memcpy(dp->mac, mac, ETH_ALEN);

	struct dp_link_th link_th=
		{.dp = dp, .inet_addr = inet_addr; .inet_port = inet_port};

	/* TODO: spawn dp_link_th and detach */

	return 0;
}


int dp_init_incoming(dp_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		int fd, sockaddr_in *addr)
{
	dp->routing = rd;
	dp->dpg = dpg;
	dp->vnet = vnet;

	memcpy(dp->addr , addr, sizeof(*addr));

	struct dp_inc_th inc_th = {.dp = dp, .fd = fd};

	/* TODO: spawn dp_incoming_th and detach */

	return 0;
}


#define LINK_STATE_TIMEOUT 10000 /* 10 seconds */
void *dp_th(void *dp_v)
{
	struct direct_peer *dp = dp_v;
	struct pollfd pfd= {.fd =dp->con_fd, .event = POLLIN | POLLRDHUP};

	for(;;) {
		int poll_val = poll(pfd, 1, LINK_STATE_TIMEOUT);
		if (poll_val == -1) {
			DP_WARN(dp, "poll %s", strerror(errno));
		} else if (poll_val == 0) {
			/* TIMEOUT */

			/* TODO3: track sequence number & rtt */
			struct pkt_probe_req probe_pkt = { .seq_num = 0 };
			dp_send_packet(dp, PT_PROBE_REQ, PL_PROBE_REQ, probe_packet);

			/* TODO: send link state packets */

		} else {
			/* read from peer connection */
			dp_recv_packet(dp);
		}
	}
}

/* dp->wlock must not be held prior to calling. (negative)
 * lock will be held following calling unless an error occours */
static int dp_send_packet(struct direct_peer *dp, enum pkt_type type,
		enum pkt_len len, void *data)
{
	int ret = dp_psend_start(dp, type, len, data, len);
	if (ret == 0)
		pthread_mutex_unlock(&dp->lock_wr);

	return ret;
}

/* dp->wlock must not be held prior to calling. (negative)
 * lock will be held following calling unless an error occours */
static int dp_psend_start(struct direct_peer *dp, enum pkt_type type,
		enum pkt_len len, void *data, size_t data_len)
{
	pthread_mutex_lock(&dp->wlock);

	/* send header allowing for "issues" */
	struct pkt_header header = {.type = htons(type), .len = htons(len)};
	int ret = dp_psend_data(dp, header, PL_HEADER);
	if (ret < 0)
		return ret;

	ret = dp_psend_data(dp, data, data_len);
	if (ret < 0)
		return ret;

	return 0;
}

/* dp->wlock must be held prior to calling. (positive)
 * lock will be held following calling unless an error occours */
static int dp_psend_data(struct direct_peer *dp, void *data, size_t data_len){
	ssize_t tmit_sz, pos = 0, rem_sz = data_len;

	/* send header allowing for "issues" */
	do {
		tmit_sz = send(dp->con_fd, data + pos, rem_sz, 0);
		if (tmit_sz < 0) {
			WARN("send header: %s", strerror(errno));
			pthread_mutex_unlock(&dp->wlock);
			return -1;
		}
		rem_sz -= tmit_sz;
		pos += tmit_sz;
	} while (rem_sz > 0);
	return 0;
}

int dp_init(dp_t *dp, ether_addr_t mac, int con_fd)
{
	memset(dp, 0, sizeof(dp));
	dp->con_fd = con_fd;
	memcpy(dp->remote_mac, mac, sizeof(dp->remote_mac));
	pthread_mutex_init(&dp->wlock, NULL);
	pthread_create(&dp->dp_th, NULL, dp_th, dp);
	return 0;
}

static int connect_host(char *host, char *port, struct sockaddr_in *res)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	struct addrinfo *ai;
	int r = getaddrinfo(host,
			port, &hints,
			&ai);
	if (r) {
		WARN("getaddrinfo: %s: %d %s",
				peer->name,
				r, gai_strerror(r));
		return -1;
	}

	/* connect to peer */
	int peer_sock =
		socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (peer_sock < 0) {
		WARN("socket: %s", strerror(errno));
		return -1;
	}

	if (connect(peer_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		WARN("connect: %s", strerror(errno));
		return -1;
	}
	
	*res = *ai->ai_addr;
	freeaddrinfo(ai);
	
	return peer_sock;
}
