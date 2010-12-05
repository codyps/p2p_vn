#include <stdlib.h>

#include <pthread.h>
#include <stdint.h>

#include "routing.h"

#define INIT_HOSTS_MEM 8

int rt_init(routing_t *rd)
{
	int ret = eag_init(rd->addrs);
	if (ret < 0)
		return ret;

	ret = pthread_rwlock_init(&rd->lock, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

void rt_destroy(routing_t *rd)
{
	eag_destroy(rd->addrs);
	pthread_rwlock_destroy(&rd->lock);
}

int rt_add_host(routing_t *rd, ether_addr_t mac)
{
	return -1;
}

int rt_add_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t dst_mac, uint64_t rtt)
{
	return -1;
}

int rt_remove_host(routing_t *rd, ether_addr_t mac)
{
	return -1;
}

int rt_set_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t **dst_macs, uint64_t *rtts, size_t len)
{

}

int rt_hosts_to_host(routing_t *rd,
		ether_addr_t src_mac, ether_addr_t dst_mac,
		struct rt_hosts **res)
{
	return -1;
}

int rt_init(routing_t *rd)
{}

void rt_destroy(routing_t *rd)
{}

int rt_dhost_add(routing_t *rd, ether_addr_t mac)
{}

int rt_dhost_add_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t dst_mac, uint32_t rtt)
{}

int rt_ihost_set_link(routing_t *rd, ether_addr_t src_mac,
		ether_addr_t **dst_macs, uint32_t **rtts, size_t len)
{}

int rt_remove_host(routing_t *rd, ether_addr_t mac)
{}

int rt_dhosts_to_host(routing_t *rd,
		ether_addr_t src_mac, ether_addr_t dst_mac,
		struct rt_hosts **res)
{}

void rt_hosts_free(routing_t *rd, struct rt_hosts *hosts)
{}

void rt_host_list_free(routing_t *rd, struct rt_hosts *hosts)
{
	while(hosts != NULL) {
		struct rt_hosts *next = hosts->next;
		free(hosts);
		hosts = next;
	}
}

