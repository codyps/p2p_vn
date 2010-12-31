#include <string.h>
#include <stdlib.h>
#include "pcon.h"

#include "stdparam.h"
#include "darray.h"

#define PC_INIT_SZ 8
#define PC_MULT 2

#define PC_CON_EASE_SEC 2

static int host_cmp(void const *v1, void const *v2)
{
	struct ip_attempt const *ia1 = v1;
	struct ip_attempt const *ia2 = v2;

	struct ipv4_host const *h1 = &ia1->host, *h2 = &ia2->host;

	int mac_cmp = memcmp(h1->mac.addr, h2->mac.addr, ETH_ALEN);
	if (mac_cmp)
		return mac_cmp;

	int ip_cmp = memcmp(&h1->in.sin_addr.s_addr,
			&h2->in.sin_addr.s_addr,
			sizeof(h2->in.sin_addr));
	if (ip_cmp)
		return ip_cmp;

	int port_cmp = memcmp(&h1->in.sin_port, &h2->in.sin_port,
			sizeof(h2->in.sin_port));
	return port_cmp;
}

static DEF_BSEARCH(pcon, struct ip_attempt, host_cmp)

int pcon_connect(pcon_t *pc, dpg_t *dpg, routing_t *rd, vnet_t *vnet,
		struct ipv4_host *host_attempt)
{
	struct ip_attempt nh = {
		.host = *host_attempt
	};

	pthread_mutex_lock(&pc->lock);

	struct timeval out = { .tv_sec = PC_CON_EASE_SEC };

	struct ip_attempt *fh = bsearch_pcon(&nh, pc->hosts, pc->h_ct);

	struct timeval now;
	gettimeofday(&now, NULL);

	if (fh) {
		/* don't connect, we have this in our list */

		struct timeval tdiff;
		timersub(&now, &fh->attempt_ts, &tdiff);

		if (timercmp(&tdiff, &out, >)) {
			/* it has been too long */
			fh->attempt_ts = now;
			pthread_mutex_unlock(&pc->lock);
			dp_create_linkstate(dpg, rd, vnet, pc, host_attempt);
			return 0;
		} else {
			pthread_mutex_unlock(&pc->lock);
			return 1;
		}
	}

	/* allocate space to add new host */
	if (pc->h_mem < (pc->h_ct + 1)) {
		size_t nsize = PC_MULT * pc->h_mem;
		struct ip_attempt *h = realloc(pc->hosts, sizeof(*pc->hosts) * nsize);
		if (!h) {
			pthread_mutex_unlock(&pc->lock);
			return -1;
		}

		pc->h_mem = nsize;
		pc->hosts = h;
	}

	nh.attempt_ts = now;
	pc->hosts[pc->h_ct] = nh;
	pc->h_ct ++;

	/* FIXME: O(n*log(n)) rather than O(n) */
	qsort(pc->hosts, pc->h_ct, sizeof(*pc->hosts), host_cmp);

	pthread_mutex_unlock(&pc->lock);
	dp_create_linkstate(dpg, rd, vnet, pc, host_attempt);
	return 0;
}

int pcon_init(pcon_t *pc)
{
	pc->hosts = malloc(sizeof(*pc->hosts) * PC_INIT_SZ);
	if (!pc->hosts) {
		return -1;
	}

	int ret = pthread_mutex_init(&pc->lock, NULL);
	if (ret < 0) {
		ret = -1;
		goto cleanup_hosts;
	}



	pc->h_mem = PC_INIT_SZ;
	pc->h_ct = 0;

	return 0;

cleanup_hosts:
	free(pc->hosts);
	return ret;
}

void pcon_destroy(pcon_t *pc)
{
	pthread_mutex_destroy(&pc->lock);
	free(pc->hosts);
}
