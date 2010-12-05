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
		   and make it nice. */
		char *pkt = malloc(pkt_length);
		ssize_t data= recv(dp->con_fd, pkt, pkt_length, MSG_WAITALL);
		/* size of the neighbors? not sure about this */
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

struct dp_init_th {
		
	direct_peer_t *dp;
	char *host;
	char *port;
};

struct dp_link_th{
	
	direct_peer_t *dp;
	ether_addr_t mac;
	__be32 inet_addr;
	__be16 inet_port;

};

struct dp_inc_th{

	direct_peer_t *dp;
	int fd;
};

int dp_init_initial(direct_peer_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		char *host, char *port){
	
	dp->rd = rd;
	dp->dpg = dpg;
	dp->vnet= vnet;

	struct dp_init_th init_th= 
		{.dp = dp, .host=host, .port=port};

	
	return 0;

}

int dp_init_linkstate(direct_peer_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		ether_addr_t mac, __be32 inet_addr, __be16 inet_port){

	dp->routing_t = rd;
	dp->dpg_t = dpg;
	dp-> ehter_addr_t = mac;
	dp->vnet= vnet;

	struct dp_link_th link_th= 
		{.dp =dp, .inet_addr= inet_addr; .inet_port = inet_port};


	return 0;
}


int dp_init_incoming(direct_peer_t *dp,
		dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		int fd){

	dp->routing_t= rd;
	dp->dpg_g= dpg;
	dp->vnet= vnet;	

	struct dp_inc_th inc_th= {.dp = dp, .fd= fd};

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

			/* TODO: send out link state packet 
			   need to keep track of sequence numbers
			   as well as time the packet */
			struct pkt_probe_req probe_packet= {.seq_num= 0};

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

int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd)
{
	memset(dp, 0, sizeof(dp));
	dp->con_fd = con_fd;
	memcpy(dp->remote_mac, mac, sizeof(dp->remote_mac));
	pthread_mutex_init(&dp->wlock, NULL);
	pthread_create(&dp->dp_th, NULL, dp_th, dp);
	return 0;
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
