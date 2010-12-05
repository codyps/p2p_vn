
#include "lnet.h"
#include <unistd.h>
#include <stdlib.h>
#include <pthreads.h>

int vnet_send(vnet_t *nd,
		void *packet, size_t size)
{
	pthread_mutex_lock(&nd->wlock);
	ssize_t w = write(nd->net_sock, packet, size);
	if (w != size) {
		WARN("packet write %zd %s", w, strerror(errno));
		pthread_mutex_unlock(&nd->wlock);
		return -1;
	}
	pthread_mutex_unlock(&nd->wlock);
	return 0;
}

int vnet_recv(vnet_t *nd, void *buf, size_t *nbyte)
{
	ssize_t len = read(nd->net_sock, buf, *nbyte);
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
	
	memcpy(nd->mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	nd->ifname = ifname;
	nd->fd = fd;

	return 0;
}
