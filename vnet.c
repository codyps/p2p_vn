
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
	*nbyte = len;
	return 0;
}

static int vnet_init_noperm(vnet_t *nd, char *ifname)
{
	nd->fd = -1;

	nd->mac.addr[0] = (random()%255) & 0xFE;
	nd->mac.addr[1] = random()%255;
	nd->mac.addr[2] = random()%255;
	nd->mac.addr[3] = random()%255;
	nd->mac.addr[4] = random()%255;
	nd->mac.addr[5] = random()%255;


	DEBUG("generated random mac");

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

	return 0;
}
