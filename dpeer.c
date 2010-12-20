#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/time.h> /* timer{sub,cmp} */

#include "debug.h"
#include "peer_proto.h"

#include "dpg.h"
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

/* we resieved a probe response. see if it makes sense */
static int dp_handle_probe_resp(dp_t *dp)
{
	struct pkt_probe_req req;
	ssize_t r = recv(dp->con_fd, &req, PL_PROBE_RESP, MSG_WAITALL);
	if (r != PL_PROBE_REQ) {
		return -1;
	}

	if (req.seq_num == dp->probe_seq) {
		struct timeval tv;
		gettimeofday(&tv, NULL);

		timersub(&tv,&dp->probe_send_time, &dp->rtt_tv);

		dp->rtt_us = tv_us(&dp->rtt_tv);

		int ret = rt_dhost_add_link(dp->rd,
				vnet_get_mac(dp->vnet) , &dp->remote_mac,
				dp->rtt_us);
		if (ret < 0) {
			DP_WARN(dp, "rt_dhost_add_link");
		}

		return ret;
	}

	return 0;
}

/* send a probe request with a random sequence number */
static int dp_send_probe_req(dp_t *dp)
{
	/* TODO: track probe */
	struct pkt_probe_req preq = {
		.seq_num = rand()
	};

	dp->probe_seq = preq.seq_num;
	gettimeofday(&dp->probe_send_time, NULL);

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

static void pkt_ipv4_unpack(const struct _pkt_ipv4_host *pip, ether_addr_t *mac, struct sockaddr_in *addr)
{
	addr->sin_family = AF_INET;
	memcpy(mac->addr, pip->mac, ETH_ALEN);
	addr->sin_addr.s_addr = pip->ip;
	addr->sin_port = pip->port;
}

static int dp_read_pkt_link_graph(dp_t *dp, size_t pkt_len)
{
	int ret;
	struct pkt_link_graph *plink = malloc(pkt_len);
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

	uint16_t e_ct = (pkt_len - PL_LINK_GRAPH_STATIC) / PL_EDGE;
	uint16_t pkt_e_ct = ntohs(plink->edge_ct);
	if (e_ct != pkt_e_ct) {
		WARN("read_link: pkt_e_ct(%d) != e_ct(%d)", pkt_e_ct, e_ct);
		ret = -2;
		goto cleanup_plink;
	}

	struct _pkt_edge *es = plink->edges;
	size_t i;
	for(i = 0; i < e_ct; i++) {
		/* attempt to connect to every unique peer in the edge
		 * packet */
		ether_addr_t mac;
		struct sockaddr_in addr;
		pkt_ipv4_unpack(&es[i].src, &mac, &addr);
		ret = pcon_connect(dp->pc, dp->dpg, dp->rd, dp->vnet, mac, addr);

		pkt_ipv4_unpack(&es[i].dst, &mac, &addr);
		ret = pcon_connect(dp->pc, dp->dpg, dp->rd, dp->vnet, mac, addr);

	}

	ret = rt_update_edges(dp->rd, es, e_ct);

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
		ether_addr_t cur_mac = vnet_get_mac(dp->vnet);
		int ret = rt_dhosts_to_host(dp->rd,
				(ether_addr_t *)&eh->ether_shost, &cur_mac,
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

	case PT_LINK_GRAPH:
		return dp_read_pkt_link_graph(dp, pkt_len);

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
		/* someone responded to our probe */
		return dp_handle_probe_resp(dp);

	default:
error_recv_flush: {
		/* unknown, read entire packet to maintain alignment. */
		DP_WARN(dp, "unknown packet type %d", pkt_type);
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

int dp_send_linkstate(dp_t *dp, struct _pkt_edge *edges, size_t e_ct)
{
	/* TODO: impliment. */
	return -1;
}

/* similar to dpg_send_linkstate, but sends to a single peer. */
static int dp_send_peer_linkstate(dp_t *dp)
{
	/* TODO: impliment */
	return -1;
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



#define DP_TIMEOUT_PROBE { .tv_sec = 1 } /* 1 second */
#define DP_TIMEOUT_LINK_MULT 10 /* 10x DP_TIMEOUT_PROBE */
static void *dp_th(void *dp_v)
{
	struct direct_peer *dp = dp_v;

	/* timeout setup */
	const struct timeval timeout_init = DP_TIMEOUT_PROBE,
		tv_zero = {};
	struct timeval before, after, wtime = {};

	int probe_ct = 0;

	/* epoll setup */
	struct epoll_event epe = {
#ifdef EPOLLRDHUP
		.events = EPOLLIN | EPOLLRDHUP
#else
		.events = EPOLLIN
#endif
	};

	int ep = epoll_create(1);
	epoll_ctl(ep, EPOLL_CTL_ADD, dp->con_fd, &epe);

	struct epoll_event ep_res;
	for(;;) {
		/* if (wtime =< 0) { */
		if (!timercmp(&wtime, &tv_zero, >)) {
			/* send probe */
			int ret = dp_send_probe_req(dp);
			if (ret < 0) {
				DP_WARN(dp, "dp_send_probe");
				/* FIXME: cleanup & die. */
			}

			/* count to 10, then send link state
			 * this will trigger on the first loop due to probe
			 * count being zero (0). */
			if (!(probe_ct % (DP_TIMEOUT_LINK_MULT))) {
				probe_ct = 0;
				/* send link state packet to all
				 * direct peers */
				dpg_send_linkstate(dp->dpg, dp->rd);
			}

			probe_ct ++;
			wtime = timeout_init;
			gettimeofday(&before, NULL);
		} else {
			before = after;
		}

		int ret = epoll_wait(ep, &ep_res, 1, tv_ms(&wtime));

		if (ret == -1) {
			DP_WARN(dp, "poll");
			/* FIXME: cleanup & die. */
		} else if (ret == 1) {
			if (ep_res.events & EPOLLIN) {
				/* read from peer connection */
				ret = dp_recv_packet(dp);
				if (ret < 0) {
					DP_WARN(dp, "dp_recv_packet");
					/* FIXME: cleanup and die */
				} else if (ret == 1) {
					/* link state updated, set probe_ct
					 * to 1 to avoid sending out another
					 * links state packet to quickly. */
					probe_ct = 1;
					dpg_send_linkstate(dp->dpg, dp->rd);
				}
			} else {
				DP_WARN(dp, "bad event, die");
				/* FIXME: cleanup and die */
			}
		}

		gettimeofday(&after, NULL);
		struct timeval dtime;
		/* dtime = after - before; */
		timersub(&after, &before, &dtime);

		/* wtime -= dtime; */
		timersub(&wtime, &dtime, &wtime);
	}
	return NULL;
}



static int dp_send_join(dp_t *dp)
{
	struct sockaddr_in *sai = &DPG_LADDR(dp->dpg);

	struct pkt_join pjoin;
	ether_addr_t my_mac = vnet_get_mac(dp->vnet);
	memcpy(&pjoin.joining_host.mac, &my_mac.addr, ETH_ALEN);
	memcpy(&pjoin.joining_host.ip, &sai->sin_addr, sizeof(sai->sin_addr));
	memcpy(&pjoin.joining_host.port, &sai->sin_port, sizeof(sai->sin_port));

	return dp_send_packet(dp, PT_JOIN, PL_JOIN, &pjoin);
}

static int dp_create_1(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc, dp_t **res)
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
	dp->pc = pc;

	*res = dp;
	return 0;
}

static void dp_cleanup_1(dp_t *dp)
{
	pthread_mutex_destroy(&dp->wlock);
	free(dp);
}

/* initial peer threads */
struct dp_initial_arg {
	dp_t *dp;
	char *host;
	char *port;
};

static void *dp_th_initial(void *dia_v)
{
	struct dp_initial_arg *dia = dia_v;
	dp_t *dp = dia->dp;
	/* - the big 3 are filled (rd, dpg, and vnet)
	 * - lock init.
	 *   nothing else done.
	 */

	/* connect to host */
	struct sockaddr_in addr;
	int fd = dp->con_fd =
		connect_host(dia->host, dia->port, &addr);
	if (fd < 0) {
		WARN("connect to %s:%s failed", dia->host, dia->port);
		goto cleanup_arg;
	}

	/* rtt & remote_mac still uninitialized.
	 * also: need to populate dpg & rd
	 */

	/* fill with junk so we can call dp_recv_header */
	memset(dp->remote_mac.addr, 0xFF, ETH_ALEN);

	/* send join */
	int ret = dp_send_join(dp);
	if (ret < 0) {
		WARN("initial: send join failed");
		goto cleanup_fd;
	}

	uint16_t pkt_len, pkt_type;
	ret = dp_recv_header(dp, &pkt_type, &pkt_len);
	if (ret) {
		WARN("initial: dp_recv_header failed %d", ret);
		goto cleanup_fd;
	}

	if (pkt_type != PT_LINK_GRAPH) {
		WARN("initial: got non-link packet as first packet.");
		goto cleanup_fd;
	}

	/* this fills in the actual mac address and adds us to
	 * the routing table. */
	ret = dp_read_pkt_link_graph(dp, pkt_len);
	if (ret) {
		WARN("initial: dp_read_pkt_link failed %d", ret);
		goto cleanup_fd;
	}

	/* as mac is now properly populated, we can add this peer to the
	 * dpg. */
	ret = dpg_insert(dp->dpg, dp);
	if (ret) {
		DP_WARN(dp, "initial: dpg_insert failed %d", ret);
		goto cleanup_fd;
	}

	/* rtt = 1sec for now */
	dp->rtt_us = 1000000;

	ret = rt_dhost_add_link(dp->rd, vnet_get_mac(dp->vnet), DPEER_MAC(dp), dp->rtt_us);
	if (ret) {
		DP_WARN(dp, "rt_dhost_add_link");
	}

	/* send probe request */
	ret = dp_send_probe_req(dp);
	if (ret) {
		DP_WARN(dp, "initial: probe_req failed %d", ret);
		goto cleanup_dpg;
	}

	free(dia);
	return dp_th(dp);

cleanup_dpg:
	dpg_remove(dp->dpg, dp);
cleanup_fd:
	close(fd);
cleanup_arg:
	free(dp);
	free(dia);
	return NULL;
}

int dp_create_initial(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc,
		char *host, char *port)
{
	dp_t *dp;
	int ret = dp_create_1(dpg, rd, vnet, pc, &dp);
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
	struct sockaddr_in addr;
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
	uint16_t pkt_type = ntohs(header.len);
	if(pkt_type == PT_JOIN_PART && pkt_len == PL_JOIN) {
		char *pkt = malloc(pkt_len);
		ssize_t r = recv(dp->con_fd, pkt, pkt_len, MSG_WAITALL);
		int x;
		for(x = 0; x < 6; x++) {
			dp->remote_mac[x] = pkt[x + 6];
		}
	}

	//if not join packet close, free stuff.
	//dp_recv_packet(dp); or something. in dpeer. recv(dp->con_fd, header, PL_HEADER, MSG_WAITALL);
	return NULL;
#endif
}


/**
 * dp_create_linkstate
 *
 * must NOT hold the pcon lock
 */
int dp_create_linkstate(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc,
		ether_addr_t mac, struct sockaddr_in addr)
{
	dp_t *dp;
	int ret = dp_create_1(dpg, rd, vnet, pc, &dp);
	if (ret < 0)
		return -1;

	/* extras for this init */
	dp->remote_mac = mac;

	ret = dpg_insert(dpg, dp);
	if (ret < 0) {
		WARN("dpg_insert failed.");
		ret = -2;
		goto cleanup_c1;
	} else if (ret) {
		/* direct peer already exists. */
		ret = 1;
		goto cleanup_c1;
	}

	struct dp_link_arg *dla = malloc(sizeof(*dla));
	if (!dla) {
		ret = -1;
		goto cleanup_dpg;
	}

	dla->dp = dp;
	dla->addr = addr;

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
cleanup_dpg:
	dpg_remove(dpg, dp);
cleanup_c1:
	dp_cleanup_1(dp);
	return ret;
}

struct dp_incoming_arg {
	dp_t *dp;
	struct sockaddr_in addr;
};

static int dp_handle_join(dp_t *dp)
{
	struct pkt_join join;
	ssize_t r = recv(dp->con_fd, &join, PL_JOIN, MSG_WAITALL);
	if (r < PL_JOIN) {
		return -1;
	}

	struct sockaddr_in addr;
	pkt_ipv4_unpack(&join.joining_host, &dp->remote_mac, &addr);

	return 0;
}

/**
 * dp_th_incoming - handle incoming peers.
 * 	+ wait for a join packet.
 * 	+ send a linkstate packet.
 * 	+ enter normal peer loop.
 */
static void *dp_th_incoming(void *dia_v)
{
	struct dp_incoming_arg *dia = dia_v;
	dp_t *dp = dia->dp;
	/* - the big 3 are filled (rd, dpg, and vnet)
	 * - lock init.
	 *   nothing else done.
	 */

	/* rtt & remote_mac still uninitialized.
	 * also: need to populate dpg & rd
	 */

	/* fill with junk so we can call dp_recv_header */
	memset(dp->remote_mac.addr, 0xFF, ETH_ALEN);

	uint16_t pkt_len, pkt_type;
	int ret = dp_recv_header(dp, &pkt_type, &pkt_len);
	if (ret) {
		DP_WARN(dp, "initial_incoming: dp_recv_header failed %d", ret);
		goto cleanup_fd;
	}

	if (pkt_type != PT_JOIN_PART || pkt_type != PL_JOIN) {
		DP_WARN(dp, "initial_incoming: got non-join packet as first packet.");
		goto cleanup_fd;
	}

	/* parse join packet for mac */
	ret = dp_handle_join(dp);
	if (ret < 0) {
		DP_WARN(dp, "initial_incoming: handle join failed.");
		goto cleanup_fd;
	}

	/* as mac is now properly populated, we can add this peer to the
	 * dpg. */
	ret = dpg_insert(dp->dpg, dp);
	if (ret) {
		DP_WARN(dp, "initial: dpg_insert failed %d", ret);
		goto cleanup_fd;
	}

	/* send the required linkstate packet */
	ret = dp_send_peer_linkstate(dp);
	if (ret) {
		DP_WARN(dp, "dp_send_peer_linkstate");
		goto cleanup_dpg;
	}

	/* rtt = 1sec for now */
	dp->rtt_us = 1000000;

	ret = rt_dhost_add_link(dp->rd, vnet_get_mac(dp->vnet), DPEER_MAC(dp), dp->rtt_us);
	if (ret) {
		DP_WARN(dp, "rt_dhost_add_link");
		goto cleanup_dpg;
	}

	free(dia);
	return dp_th(dp);

cleanup_dpg:
	dpg_remove(dp->dpg, dp);
cleanup_fd:
	close(dp->con_fd);
	free(dp);
	free(dia);
	return NULL;
}

int dp_create_incoming(dpg_t *dpg, routing_t *rd, vnet_t *vnet, pcon_t *pc,
		int fd, struct sockaddr_in *addr)
{
	struct dp_incoming_arg *dia = malloc(sizeof(*dia));
	if (!dia) {
		return -1;
	}

	dp_t *dp;
	int ret = dp_create_1(dpg, rd, vnet, pc, &dp);
	if (ret < 0) {
		free(dia);
		return -1;
	}

	dia->dp = dp;
	dia->addr = *addr;

	/* extras for this init */
	dp->con_fd = fd;

	/* spawn & detach */
	ret = pthread_create(&dp->dp_th, NULL, dp_th_incoming, dia);
	if (ret < 0) {
		free(dia);
		dp_cleanup_1(dp);
		return -2;
	}

	ret = pthread_detach(dp->dp_th);
	if (ret < 0)
		return -4;

	return 0;
}

