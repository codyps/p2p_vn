#include "dpeer.h"
#include "poll.h"

static int dp_recv_packet(struct direct_peer *dp)
{
	struct pkt_header header;
	ssize_t r = recv(dp->con_fd, header, PL_HEADER, MSG_WAITALL);
	if(r == -1) {
		/* XXX: on client & server ctrl-c, this fires */
		WARN("Packet not read %s", strerror(errno));
		return -errno;
	} else if (r < PL_HEADER) {
		WARN("client disconnected.");
		return 1;
	}

	uint16_t pkt_length = ntohs(header.type);
	uint16_t pkt_type   = ntohs(header.length);

	switch (pkt_type) {
	case PT_DATA:
		break;

	case PT_LINK:
		break;

	case PT_JOIN_PART:
		switch (pkt_length) {
		case PL_JOIN:
			break;
		case PL_PART:
			break;
		}
		break;

	case PT_QUIT:
		break;

	case PT_PROBE_REQ:
		/* someone is requesting a probe responce */
		break;

	case PT_PROBE_RESP:
		/* someone responded to our probe */
		break;
	default:
		/* unknown, read entire packet to maintain alignment. */
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




void *dp_out_th(void *dp_v)
{

}

void *dp_in_th(void *dp_v)
{
	struct direct_peer *dp = dp_v;
	struct pollfd pfd= {.fd =dp->con_fd, .event = POLLIN | POLLRDHUP};
	int poll_val;
	int time_out= 10000;  /* 10 seconds */

	while (1){

		poll_val = poll(pfd, 1, time_out);
		if(pol_val == -1){
			perror("poll");
		}
		/* poll returned */

		/* timeout reached, need to send probe/link state packets */
		else if(pol_val == 0){

			/* TODO: need to keep track of sequence numbers
			   as well as time the packet */
	 
			struct pkt_probe_req probe_packet= {.seq_num= 0};
			peer_send_packet(dp, PT_PROBE_REQ, PL_PROBE_REQ, probe_packet);
			
		}

		/* read from peer connection */
		else {
			dp_recv_packet(dp);

		}
	}
	
}

static int peer_send_packet(struct direct_peer *dp, enum pkt_type type, enum pkt_len len, void *data)
{
	struct pkt_header header = {.type = htons(type), .len = htons(len)};
	ssize_t tmit_sz, pos = 0, rem_sz = sizeof(header);
	pthread_mutex_lock(dp->lock_wr);

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


void *dp_route_th(void *dp_v)
{
	struct direct_peer *dp = dp_v;

	pthread_create(&dp->dp_th, NULL, dp_out_th, dp);


	for(;;) {
		/* check for packets on in queue */
		/* if found, ask route for a route */
			/* add the packets to the out queue of the next
			 * nodes */

		/* check if we're still in busieness */
			/* if no, wait for death */
				/* free reasources & exit */
	}
}


int dp_init(direct_peer_t *dp, ether_addr_t mac, int con_fd)
{
	memset(dp, 0, sizeof(dp));

	dp->con_fd = con_fd;

	memcpy(dp->remote_mac, mac, sizeof(dp->remote_mac));

	pthread_mutex_init(&dp->dlock_out, NULL);
	pthread_mutex_init(&dp->dlock_in, NULL);

	pthread_create(&dp->th_route, NULL, dp_route_th, dp);

	return 0;
}
