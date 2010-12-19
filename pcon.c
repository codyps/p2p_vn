#include <string.h>
#include <stdlib.h>
#include "pcon.h"

#define PC_INIT_SZ 8
#define PC_MULT 2

#define PC_CON_EASE_SEC 2

static int host_cmp(const void *v1, const void *v2)
{
	const struct ipv4_host *h1 = v1;
	const struct ipv4_host *h2 = v2;

	int mac_cmp = memcmp(h1->mac.addr, h2->mac.addr, ETH_ALEN);
	if (mac_cmp)
		return mac_cmp;

	int ip_cmp = memcmp(&h1->in.sin_addr.s_addr, &h2->in.sin_addr.s_addr, sizeof(h2->in.sin_addr));
	if (ip_cmp)
		return ip_cmp;

	int port_cmp = memcmp(&h1->in.sin_port, &h2->in.sin_port, sizeof(h2->in.sin_port));
	return port_cmp;
}

int pcon_should_connect(pcon_t *pc, ether_addr_t mac, struct sockaddr_in addr)
{
	struct ipv4_host nh = {
		.mac = mac,
		.in = addr
	};

	struct timeval out = { .tv_sec = PC_CON_EASE_SEC };

	struct ipv4_host *fh = bsearch(&nh, pc->hosts, pc->h_ct,
				sizeof(*pc->hosts), host_cmp);

	struct timeval now;
	gettimeofday(&now, NULL);

	if (fh) {
		/* don't connect, we have this in our list */

		struct timeval tdiff;
		timersub(&now, &fh->attempt_ts, &tdiff);

		if (timercmp(&tdiff, &out, >)) {
			/* it has been too long */
			fh->attempt_ts = now;
			return 0;
		} else {
			return 1;
		}
	}

	/* allocate space to add new host */
	if (pc->h_mem < (pc->h_ct + 1)) {
		size_t nsize = PC_MULT * pc->h_mem;
		struct ipv4_host *h = realloc(pc->hosts, sizeof(*pc->hosts) * nsize);
		if (!h)
			return -1;

		pc->h_mem = nsize;
	}

	nh.attempt_ts = now;
	pc->hosts[pc->h_ct] = nh;
	pc->h_ct ++;

	/* FIXME: O(n*log(n)) rather than O(n) */
	qsort(pc->hosts, pc->h_ct, sizeof(*pc->hosts), host_cmp);

	return 0;
}

int pcon_init(pcon_t *pc)
{
	pc->hosts = malloc(sizeof(*pc->hosts) * PC_INIT_SZ);
	if (!pc->hosts) {
		return -1;
	}

	pc->h_mem = PC_INIT_SZ;
	pc->h_ct = 0;

	return 0;
}

void pcon_destroy(pcon_t *pc)
{
	free(pc->hosts);
}
