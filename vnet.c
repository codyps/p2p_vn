
/* open */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* tun */
#include <linux/if_tun.h>

/* netdevice (7) */
#include <sys/ioctl.h>
#include <net/if.h>

#include <string.h> /* strerror */
#include <errno.h> /* errno */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "debug.h"
#include "vnet.h"

/* data for each raw read thread */
struct vnet_reader_arg {
	vnet_t *vnet;
	routing_t *rd;
	dpg_t *dpg;
};

#define DATA_MAX_LEN UINT16_MAX
static void *vnet_reader_th(void *arg)
{
	struct vnet_reader_arg *vra = arg;
	void *data = malloc(DATA_MAX_LEN);
	DEBUG("spawned: vnet_reader_th");
	for(;;) {
		size_t pkt_len = DATA_MAX_LEN;
		int r = vnet_recv(vra->vnet, data,
				&pkt_len);
		if (r < 0) {
			WARN("vnet_recv failed");
			return NULL;
		}

		struct ether_header *eh = data;
		ether_addr_t dst_mac;
		memcpy(dst_mac.addr, eh->ether_dhost, ETH_ALEN);

		struct rt_hosts *hosts;
		ether_addr_t mac = vnet_get_mac(vra->vnet);
		r = rt_dhosts_to_host(vra->rd, mac, dst_mac, &hosts);
		if (r < 0) {
			WARN("vnet :: rt_dhosts_to_host failed %d", r);
			continue;
		}

		if (hosts)
			DEBUG("vnet :: dhosts to host gave some hosts");
		else
			DEBUG("vnet :: dhosts to host gave no hosts :(");

		struct rt_hosts *nhost = hosts;
		while (nhost) {
			uint8_t *m = nhost->addr->mac.addr;
			DEBUG("vnet :: sending packet to host "
				"%02x:%02x:%02x:%02x:%02x:%02x",
				m[0],m[1],m[2],m[3],m[4],m[5]);

			ssize_t l = dp_send_data(dp_from_ip_host(nhost->addr),
					data, pkt_len);
			if (l < 0) {
				WARN("vnet :: dp_send_data returned %zi", l);
			}
			nhost = nhost->next;
		}

		rt_hosts_free(vra->rd, hosts);
	}
	return vra;
}

int vnet_spawn_listener(vnet_t *vnet, routing_t *rd, dpg_t *dpg)
{
	if (vnet->fd == -1) {
		DEBUG("not spawning vnet listener.");
		return 0;
	}

	struct vnet_reader_arg *vra = malloc(sizeof(*vra));
	if (!vra)
		return -1;

	vra->vnet = vnet;
	vra->rd = rd;
	vra->dpg = dpg;

	pthread_attr_t attr;
	int ret = pthread_attr_init(&attr);
	if (ret < 0) {
		ret = -3;
		goto cleanup_vra;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret < 0) {
		ret = -2;
		goto cleanup_attr;
	}

	pthread_t vnet_th;
	ret = pthread_create(&vnet_th, &attr, vnet_reader_th, vra);
	if (ret) {
		DIE("pthread_create vnet_th failed.");
	}

	return 0;

cleanup_attr:
	pthread_attr_destroy(&attr);
cleanup_vra:
	free(vra);
	return ret;
}

ether_addr_t vnet_get_mac(vnet_t *vn)
{
	ether_addr_t m = vn->mac;
	return m;
}

int vnet_send(vnet_t *nd,
		void *packet, size_t size)
{
	if (nd->fd == -1) {
		WARN("vnet_send called on fake vnet");
		return 0;
	}
	pthread_mutex_lock(&nd->wlock);
	ssize_t w = write(nd->fd, packet, size);
	if (w != size) {
		WARN("packet write %zd %s", w, strerror(errno));
		pthread_mutex_unlock(&nd->wlock);
		return -1;
	}
	pthread_mutex_unlock(&nd->wlock);
	return 0;
}

int vnet_get_mtu(vnet_t *nd)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, nd->ifname, IFNAMSIZ);

	/* throw away socket for ioctl */
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	int ret = ioctl(sock, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		close(sock);
		return -2;
	}

	close(sock);

	return ifr.ifr_mtu;
}

int vnet_recv(vnet_t *nd, void *buf, size_t *nbyte)
{
	ssize_t len = read(nd->fd, buf, *nbyte);
	if (len < 0) {
		WARN("packet read died %zd, %s",len, strerror(errno));
		return -1;
	}
	DEBUG("vnet - got packet of len %zu", len);
	*nbyte = len;
	return 0;
}

static int vnet_init_noperm(vnet_t *nd, char *ifname)
{
	WARN("vnet falling back on fake");
	nd->fd = -1;

	nd->mac.addr[0] = (random()%255) & 0xFE;
	nd->mac.addr[1] = random()%255;
	nd->mac.addr[2] = random()%255;
	nd->mac.addr[3] = random()%255;
	nd->mac.addr[4] = random()%255;
	nd->mac.addr[5] = random()%255;


	DEBUG("generated random mac %x:%x:%x:%x:%x:%x",
			nd->mac.addr[0],
			nd->mac.addr[1],
			nd->mac.addr[2],
			nd->mac.addr[3],
			nd->mac.addr[4],
			nd->mac.addr[5]);

	return 0;
}

int vnet_init(vnet_t *nd, char *ifname)
{
	int fd, err;
	struct ifreq ifr;
	nd->ifname = ifname;

	/* pthread */
	err = pthread_mutex_init(&nd->wlock, NULL);
	if (err < 0) {
		return err;
	}

	if ( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		WARN("open");
		return vnet_init_noperm(nd, ifname);
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if ( (err = ioctl(fd, TUNSETIFF, &ifr)) < 0 ) {
		WARN("TUNSETIFF: %s", strerror(errno));
		close(fd);
		return vnet_init_noperm(nd, ifname);
	}

	/* get mac */
	if ( (err = ioctl(fd, SIOCGIFHWADDR, &ifr)) < 0) {
		WARN("SIOCGIFHWADDR: %s", strerror(errno));
		close(fd);
		return vnet_init_noperm(nd, ifname);
	}

	memcpy(nd->mac.addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	nd->fd = fd;
	DEBUG("using adaptor mac %x:%x:%x:%x:%x:%x",
			nd->mac.addr[0],
			nd->mac.addr[1],
			nd->mac.addr[2],
			nd->mac.addr[3],
			nd->mac.addr[4],
			nd->mac.addr[5]);

	return 0;
}
