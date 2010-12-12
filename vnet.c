
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

int vnet_set_mac(vnet_t *vn, ether_addr_t *mac)
{
	pthread_rwlock_wrlock(&vn->m_lock);
	vn->mac = *mac;
	pthread_rwlock_unlock(&vn->m_lock);
	return 0;
}

ether_addr_t vnet_get_mac(vnet_t *vn)
{
	pthread_rwlock_rdlock(&vn->m_lock);
	ether_addr_t m = vn->mac;
	pthread_rwlock_unlock(&vn->m_lock);
	return m;
}

int vnet_send(vnet_t *nd,
		void *packet, size_t size)
{
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
	if (ret < 0)
		return -2;

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

int vnet_init(vnet_t *nd, char *ifname)
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

	/* get mac */
	if ( (err = ioctl(fd, SIOCGIFHWADDR, &ifr)) < 0) {
		WARN("SIOCGIFHWADDR: %s", strerror(errno));
		close(fd);
		return err;
	}

	/* pthread */
	err = pthread_mutex_init(&nd->wlock, NULL);
	if (err < 0) {
		close(fd);
		return err;
	}

	err = pthread_rwlock_init(&nd->m_lock, NULL);
	if (err < 0) {
		pthread_mutex_destroy(&nd->wlock);
		close(fd);
		return err;
	}

	memcpy(nd->mac.addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	nd->ifname = ifname;
	nd->fd = fd;

	return 0;
}
