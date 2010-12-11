#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "peer_proto.h"

#include "dpeer.h"
#include "poll.h"

/*** static functions ***/

/* dp->wlock must be held prior to calling. (positive)
 * lock will be held following calling unless an error occours */
static int dp_psend_data(struct direct_peer *dp, void *data, size_t data_len){
	ssize_t tmit_sz, pos = 0, rem_sz = data_len;

	/* send header allowing for "issues" */
	do {
		tmit_sz = send(dp->con_fd, data + pos, rem_sz, 0);
		if (tmit_sz < 0) {
			WARN("psend data: %s", strerror(errno));
			pthread_mutex_unlock(&dp->wlock);
			return -1;
		}
		rem_sz -= tmit_sz;
		pos += tmit_sz;
	} while (rem_sz > 0);
	return 0;
}

/* dp->wlock must not be held prior to calling. (negative)
 * lock will be held following calling unless an error occours */
static int dp_psend_start(struct direct_peer *dp, enum pkt_type type,
		enum pkt_len len, void *data, size_t data_len)
{
	pthread_mutex_lock(&dp->wlock);

	/* send header allowing for "issues" */
	struct pkt_header header = {
		.type = htons(type),
		.len = htons(len)
	};

	int ret = dp_psend_data(dp, &header, PL_HEADER);
	if (ret < 0)
		return ret;

	ret = dp_psend_data(dp, data, data_len);
	if (ret < 0)
		return ret;

	return 0;
}

/* dp->wlock must not be held prior to calling. (negative)
 * lock will be held following calling unless an error occours */
static int dp_send_packet(struct direct_peer *dp, enum pkt_type type,
		uint16_t len, void *data)
{
	int ret = dp_psend_start(dp, type, len, data, len);
	if (ret == 0)
		pthread_mutex_unlock(&dp->wlock);

	return ret;
}

/* read the contents of the probe request,
 * send a probe responce
 */
static int dp_handle_probe_req(dp_t *dp)
{
	struct pkt_probe_req req;
	ssize_t r = recv(dp->con_fd, &req, PL_PROBE_REQ, MSG_WAITALL);
	if (r != PL_PROBE_REQ) {
		return -1;
	}

	struct pkt_probe_resp presp = {
		.seq_num = req.seq_num
	};

	int ret = dp_send_packet(dp, PT_PROBE_RESP,
		PL_PROBE_RESP, &presp);

	return ret;
}

static int dp_send_probe_req(dp_t *dp)
{
	/* TODO: track probe */
	struct pkt_probe_req preq = {
		.seq_num = 0
	};

	int ret = dp_send_packet(dp, PT_PROBE_REQ,
		PL_PROBE_REQ, &preq);

	return ret;
}

/* requires con_fd and mac be set to something (mac may be invalid) */
static int dp_recv_header(dp_t *dp, uint16_t *pkt_type, uint16_t *pkt_len)
{
	struct pkt_header header;
	ssize_t r = recv(dp->con_fd, &header, PL_HEADER, MSG_WAITALL);
	if(r == -1) {
		DP_WARN(dp, "recv packet: %s", strerror(errno));
		return -errno;
	} else if (r < PL_HEADER) {
		DP_WARN(dp, "client disconnected.");
		return 1;
	}

	*pkt_len  = ntohs(header.type);
	*pkt_type = ntohs(header.len);
	return 0;
}

static int dp_read_pkt_link(dp_t *dp, size_t pkt_len)
{
	int ret;
	struct pkt_link *plink = malloc(pkt_len);
	if (!plink) {
		WARN("read_link: plink alloc failed.");
		return -1;
	}

	ssize_t r = recv(dp->con_fd, plink, pkt_len, MSG_WAITALL);
	if (r != pkt_len) {
		WARN("read_link: linkstate packet recv failed");
		ret = -1;
		goto cleanup_plink;
	}

	/* populate our remote mac */
	memcpy(dp->remote_mac.addr, plink->vec_src_host.mac, ETH_ALEN);

	uint16_t n_ct = (pkt_len - PL_LINK_STATIC) / PL_NEIGHBOR;
	uint16_t pkt_n_ct = ntohs(plink->neighbor_ct);
	if (n_ct != pkt_n_ct) {
		WARN("read_link: pkt_n_ct(%d) != n_ct(%d)", pkt_n_ct, n_ct);
		ret = -2;
		goto cleanup_plink;
	}

	struct _pkt_neighbor *ns = plink->neighbors;

	ret = rt_ihost_set_link(dp->rd,
			(ether_addr_t *)plink->vec_src_host.mac,
			ns, n_ct);

	/* spawn a new direct peer for each neighbor */
	/* FIXME: don't try again if it failed before? */
	uint16_t i;
	for (i = 0; i < n_ct; i++) {
		/* error returns don't matter here */
		dp_create_linkstate(dp->dpg, dp->rd, dp->vnet,
			(ether_addr_t *)ns[i].host.mac,
			ns[i].host.ip, ns[i].host.port);
	}

	if (ret < 0) {
		WARN("rt_ihost_set_link failed: %d", ret);
	} else {
		ret = 0;
	}

cleanup_plink:
	free(plink);
	return ret;
}

static int dp_recv_packet(struct direct_peer *dp)
{

	uint16_t pkt_len, pkt_type;
	int ret = dp_recv_header(dp, &pkt_type, &pkt_len);
	if (ret)
		return ret;

	switch (pkt_type) {
	case PT_DATA: {
		void *pkt = malloc(pkt_len);
		ssize_t r = recv(dp->con_fd, pkt, pkt_len, MSG_WAITALL);
		if (r != pkt_len) {
			DP_WARN(dp, "pkt recv failed");
			free(pkt);
			return -1;
		}

		struct ether_header *eh = pkt;
		struct rt_hosts *hosts;
		int ret = rt_dhosts_to_host(dp->rd,
				(ether_addr_t *)&eh->ether_shost, &VNET_MAC(dp->vnet),
				(ether_addr_t *)&eh->ether_dhost, &hosts);

		if (ret < 0) {
			DP_WARN(dp, "rt_dhosts_to_host %d", ret);
			free(pkt);
			return -1;
		}

		struct rt_hosts *nhost = hosts;

		while (nhost) {
			ssize_t l = dp_send_data(dp_from_eth(nhost->addr),
					pkt, pkt_len);
			if (l < 0) {
				DP_WARN(dp, "dp_send_data: %s", strerror(l));
			}
			nhost = nhost->next;
		}

		rt_hosts_free(dp->rd, hosts);
		free(pkt);
		break;
	}

	case PT_LINK:
		return dp_read_pkt_link(dp, pkt_len);

	case PT_JOIN_PART:
#if 0
		switch (pkt_len) {
		case PL_JOIN:
			break;
		case PL_PART:
			break;
		default:
			goto error_recv_flush;
		}
		break;
#endif
		goto error_recv_flush;

	case PT_QUIT:
		/* TODO: ignore this more effectively? */
		goto error_recv_flush;

	case PT_PROBE_REQ:
		/* someone is requesting a probe response */
		return dp_handle_probe_req(dp);

	case PT_PROBE_RESP:
		/* TODO: someone responded to our probe,
		 * update rtt */
		goto error_recv_flush;

	default:
error_recv_flush: {
		/* unknown, read entire packet to maintain alignment. */
		void *pkt = malloc(pkt_len);
		ssize_t r = recv(dp->con_fd, pkt, pkt_len, MSG_WAITALL);
		if (r != pkt_len) {
			WARN("pkt recv failed");
			free(pkt);
			return -1;
		}
		return 0;
	}

	} /* switch(pkt_type) */

	return 0;
}

int dp_send_data(dp_t *dp, void *data, size_t len)
{
	return dp_send_packet(dp, PT_DATA, len, data);
}

static int connect_host(char *host, char *port, struct sockaddr_in *res)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	struct addrinfo *ai;
	int ret = getaddrinfo(host,
			port, &hints,
			&ai);
	if (ret) {
		WARN("getaddrinfo: %s: %d %s",
				host, ret, gai_strerror(ret));
		return -1;
	}

	/* connect to peer */
	int peer_sock =
		socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if (peer_sock < 0) {
		WARN("socket: %s", strerror(errno));
		ret = -2;
		goto cleanup_ai;
	}

	if (connect(peer_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		WARN("connect: %s", strerror(errno));
		ret = -3;
		goto cleanup_sock;
	}

	if (ai->ai_addrlen != sizeof(*res)) {
		WARN("bad size of sockaddr");
		ret = -4;
		goto cleanup_sock;
	}

	*res = *(struct sockaddr_in *)ai->ai_addr;
	freeaddrinfo(ai);

	return peer_sock;

cleanup_sock:
	close(peer_sock);
cleanup_ai:
	freeaddrinfo(ai);
	return ret;
}


#define LINK_STATE_TIMEOUT 10000 /* 10 seconds */
static void *dp_th(void *dp_v)
{
	struct direct_peer *dp = dp_v;
	struct pollfd pfd = {
		.fd = dp->con_fd,
		.events = POLLIN /*| POLLRDHUP*/
	};

	for(;;) {
		int poll_val = poll(&pfd, 1, LINK_STATE_TIMEOUT);
		if (poll_val == -1) {
			DP_WARN(dp, "poll %s", strerror(errno));
			/* FIXME: cleanup & die. */
		} else if (poll_val == 0) {
			/* TIMEOUT */

			/* TODO3: track sequence number & rtt */
			int ret = dp_send_probe_req(dp);
			if (ret < 0) {
				DP_WARN(dp, "dp_send_probe");
				/* FIXME: cleanup & die. */
			}

			/* TODO: send link state packets */

		} else {
			/* read from peer connection */
			dp_recv_packet(dp);
		}
	}

	return NULL;
}


/* initial peer threads */
struct dp_initial_arg {
	dp_t *dp;
	char *host;
	char *port;
};

static void *dp_th_initial(void *dpa_v)
{
	struct dp_initial_arg *dpa = dpa_v;
	/* - the big 3 are filled (rd, dpg, and vnet)
	 * - lock init.
	 *   nothing else done.
	 */

	/* connect to host */
	int fd = dpa->dp->con_fd =
		connect_host(dpa->host, dpa->port, &dpa->dp->addr);
	if (fd < 0) {
		WARN("connect to %s:%s failed", dpa->host, dpa->port);
		goto cleanup_arg;
	}

	/* rtt & remote_mac still uninitialized.
	 * also: need to populate dpg & rd
	 */

	/* send join */
	struct sockaddr_in *sai = &DPG_LADDR(dpa->dp->dpg);

	struct pkt_join pjoin;
	memcpy(&pjoin.joining_host.mac, &VNET_MAC(dpa->dp->vnet), ETH_ALEN);
	memcpy(&pjoin.joining_host.ip, &sai->sin_addr, sizeof(sai->sin_addr));
	memcpy(&pjoin.joining_host.port, &sai->sin_port, sizeof(sai->sin_port));

	int ret = dp_send_packet(dpa->dp, PT_JOIN, PL_JOIN, &pjoin);
	if (ret < 0) {
		WARN("initial: send join failed");
		goto cleanup_fd;
	}

	/* fill with junk so we can call dp_recv_header */
	memset(dpa->dp->remote_mac.addr, 0xFF, ETH_ALEN);

	uint16_t pkt_len, pkt_type;
	ret = dp_recv_header(dpa->dp, &pkt_type, &pkt_len);
	if (ret) {
		WARN("initial: dp_recv_header failed %d", ret);
		goto cleanup_fd;
	}

	if (pkt_type != PT_LINK) {
		WARN("initial: got non-link packet as first packet.");
		goto cleanup_fd;
	}

	/* this fills in the actuall mac address */
	ret = dp_read_pkt_link(dpa->dp, pkt_len);
	if (ret) {
		WARN("initial: dp_read_pkt_link failed %d", ret);
		goto cleanup_fd;
	}

	/* rtt = 1 for now */
	dpa->dp->rtt = 1;

	/* send probe request */
	ret = dp_send_probe_req(dpa->dp);
	if (ret) {
		WARN("initial: probe_req failed %d", ret);
		goto cleanup_fd;
	}

	return dp_th(dpa->dp);

cleanup_fd:
	close(fd);
cleanup_arg:
	free(dpa->dp);
	free(dpa_v);
	return NULL;
}

static int dp_create_1(dpg_t *dpg, routing_t *rd, vnet_t *vnet, dp_t **res)
{
	dp_t *dp = malloc(sizeof(*dp));
	if (!dp) {
		return -1;
	}


	int ret = pthread_mutex_init(&dp->wlock, NULL);
	if (ret < 0) {
		free(dp);
		return -2;
	}

	dp->rd = rd;
	dp->dpg = dpg;
	dp->vnet = vnet;

	*res = dp;
	return 0;
}

static void dp_cleanup_1(dp_t *dp)
{
	pthread_mutex_destroy(&dp->wlock);
	free(dp);
}

int dp_create_initial(dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		char *host, char *port)
{
	dp_t *dp;
	int ret = dp_create_1(dpg, rd, vnet, &dp);
	if (ret < 0)
		return -1;

	/* host & port are allocated for the exec and will never be freed */
	struct dp_initial_arg *dia = malloc(sizeof(*dia));
	if (!dia) {
		ret = -3;
		goto cleanup_c1;
	}

	dia->dp = dp;
	dia->host = host;
	dia->port = port;

	ret = pthread_create(&dp->dp_th, NULL, dp_th_initial, &dia);
	if (ret < 0) {
		ret = -4;
		goto cleanup_dia;
	}

	ret = pthread_detach(dp->dp_th);
	if (ret < 0) {
		/* as the thread started succesfully, it is responsible
		 * for it's own cleanup */
		return -4;
	}

	return 0;

cleanup_dia:
	free(dia);
cleanup_c1:
	dp_cleanup_1(dp);
	return ret;
}

struct dp_link_arg {
	dp_t *dp;
	__be32 inet_addr;
	__be16 inet_port;
};

static void *dp_th_linkstate(void *dp_v)
{
	dp_t *dp = dp_v;
	return dp;
#if 0
	struct pkt_header header;
	ssize_t r = recv(dp->con_fd, &header, PL_HEADER, MSG_WAITALL);
	if(r == -1) {
		/* XXX: on client & server ctrl-c, this fires */
		DP_WARN(dp, "recv packet: %s", strerror(errno));
		return -errno;
	} else if (r < PL_HEADER) {
		DP_WARN(dp, "client disconnected.");
		return 1;
	}

	uint16_t pkt_len = ntohs(header.type);
	uint16_t pkt_type   = ntohs(header.len);
	if(pkt_type == PT_JOIN_PART && pkt_len == PL_JOIN) {
		char *pkt = malloc(pkt_len);
		ssize_t r = recv(dp->con_fd, pkt, pkt_len, MSG_WAITALL);
		int x;
		for(x = 0; x < 6; x++) {
			dp->remote_mac[x] = pkt[x + 6];
		}
	}

	//if not join packet close, free stuff.
	//dp_recvPcket (look up) or something. in dpeer. recv(dp->con_fd, header, PL_HEADER, MSG_WAITALL);

	return NULL;
#endif
}


int dp_create_linkstate(dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		ether_addr_t *mac, __be32 inet_addr, __be16 inet_port)
{
	dp_t *dp;
	int ret = dp_create_1(dpg, rd, vnet, &dp);
	if (ret < 0)
		return -1;

	/* extras for this init */
	dp->remote_mac = *mac;

	/* inet_addr & inet_port need copying */
	struct dp_link_arg *dla = malloc(sizeof(*dla));
	if (!dla) {
		ret = -1;
		goto cleanup_c1;
	}

	dla->dp = dp;
	dla->inet_addr = inet_addr;
	dla->inet_port = inet_port;

	ret = pthread_create(&dp->dp_th, NULL, dp_th_linkstate, &dla);
	if (ret < 0) {
		ret = -2;
		goto cleanup_dla;
	}

	ret = pthread_detach(dp->dp_th);
	if (ret < 0)
		return -4;

	return 0;

cleanup_dla:
	free(dla);
cleanup_c1:
	dp_cleanup_1(dp);
	return ret;
}

static void *dp_th_incoming(void *dp_v)
{
	dp_t *dp = dp_v;


	/* TODO: handle. a subset of initial peer */\
	return dp;
}

int dp_create_incoming(dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		int fd, struct sockaddr_in *addr)
{
	dp_t *dp;
	int ret = dp_create_1(dpg, rd, vnet, &dp);
	if (ret < 0) {
		return -1;
	}

	/* extras for this init */
	memcpy(&dp->addr, addr, sizeof(*addr));
	dp->con_fd = fd;

	/* spawn & detach */
	ret = pthread_create(&dp->dp_th, NULL, dp_th_incoming, dp);
	if (ret < 0) {
		dp_cleanup_1(dp);
		return -2;
	}

	ret = pthread_detach(dp->dp_th);
	if (ret < 0)
		return -4;

	return 0;
}

