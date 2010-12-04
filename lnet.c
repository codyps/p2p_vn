
static int lnd_send(struct local_netif *nd,
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
