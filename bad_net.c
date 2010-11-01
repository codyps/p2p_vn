#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "debug.h"
#include "net.h"
#include "bad_net.h"

#include <stddef.h> /* offsetof */

/* packet (7) */
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

/* filtering */
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/filter.h>


/* tcpdump -d \( not ip \) or \( ip net 192.168.0.0/24 \)
 (000) ldh      [12]
 (001) jeq      #0x800           jt 2	jf 9
 (002) ld       [26]
 (003) and      #0xffffff00
 (004) jeq      #0xc0a80000      jt 9	jf 5
 (005) ld       [30]
 (006) and      #0xffffff00
 (007) jeq      #0xc0a80000      jt 9	jf 8
 (008) ret      #0
 (009) ret      #65535
 */

/* __SUBNET_MASK__ and __SUBNET_VAL__ need to be replaced with actual values
 * (at runtime)
 * Note: BPF_LD converts things to host byte order, so SUBNET_* need to be
 * in host byte order aswell.
 */
#define FILT_IP_CHECK 4
#define FILT_SUB_CHECK 3
static struct sock_filter net_filter[] = {
	/* 0: Load h_proto in ethernet header */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsetof(struct ethhdr, h_proto)),

	/* 1: Check for IP packets. T = next, F = done succ. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0/*2-1-1*/, 3/*5-1-1*/),

	/* 2: load ip src */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			ETH_HLEN + offsetof(struct iphdr, saddr)),

	/* 3: And it to compare for subnet */
	BPF_STMT(BPF_ALU | BPF_AND, 0xdeadbeef /*__SUBNET_MASK__*/ ),

	/* 4: is ipsrc == the address assigned to the fake virtual? */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			0xdeadbeef /*__SUBNET_VAL__*/, 0/*5-4-1*/, 1/*6-4-1*/),

	/* 5: accept entire packet */
	BPF_STMT(BPF_RET | BPF_K, -1),

	/* 6: reject packet */
	BPF_STMT(BPF_RET | BPF_K, 0)
};

static struct sock_fprog fcode = {
	.len = sizeof(net_filter) / sizeof(*net_filter),
	.filter = net_filter
};

int bad_net_recv_packet(struct net_data *nd, void *buf, size_t *nbyte)
{
	ssize_t r;
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	socklen_t sl = sizeof(sa);

	r = recvfrom(nd->net_sock, buf, *nbyte, 0,
			(struct sockaddr *)&sa, &sl);
	if (r < 0) {
		WARN("packet read died %zd, %s",r, strerror(errno));
		return -1;
	}
	*nbyte = r;
	return 0;
}

int bad_net_send_packet(struct net_data *nd,
		void *packet, size_t size)
{
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_ifindex = nd->ifindex,
		.sll_protocol = htons(ETH_P_ALL)
	};

	ssize_t c = sendto(nd->net_sock, packet, size, 0,
			(struct sockaddr *)&sa,
			sizeof(sa));

	if (c != size) {
		WARN("packet write died %zd.", c);
		return -1;
	}
	return 0;
}

#ifdef DEBUG
static void print_fcode(struct sock_fprog *fcode)
{
	size_t i;
	for (i = 0; i < fcode->len; i++) {
		struct sock_filter *op = fcode->filter + i;
		printf("{ 0x%x, %d, %d, 0x%08x },\n",
				op->code, op->jt, op->jf, op->k);
	}
}
#endif

# define CMBSTR3(s1, i, s2) CMBSTR3_(s1,i,s2)
# define CMBSTR3_(str1, ins, str2) str1 #ins str2
int bad_net_init(struct net_data *nd, char *ifname)
{
	WARN("using bad network initialization, kernel will never see packets");
	/** using PACKET sockets, packet(7) **/
	/* reception with packet sockets will be fine,
	 * documentation on sending is sketchy. especially
	 * what the contents of sll_addr should be
	 */

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		WARN("socket(AF_PACKET,SOCK_RAW, ...): %s", strerror(errno));
		return sock;
	}

	/* SIOCGIFINDEX
	 * see netdevice(7) */
	struct ifreq ifreq;

	/* overflow bad */
	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
	int ret = ioctl(sock, SIOCGIFINDEX, &ifreq);
	if (ret < 0) {
		WARN(CMBSTR3("SIOCGIFINDEX %",IFNAMSIZ,"s: %s"),
			ifreq.ifr_name, strerror(errno));
		close(sock);
		return ret;
	}

	int ifindex = ifreq.ifr_ifindex;

	struct sockaddr_ll sll_bind;

	/*  When you send packets it is enough to specify sll_family, sll_addr,
	 *  sll_halen, sll_ifindex. The other fields should be 0. sll_hatype
	 *  and sll_pkttype are set on received packets for your
	 *  information. For bind only sll_protocol and sll_ifindex are used.
	 */

	/* All needed for bind */
	sll_bind.sll_family = AF_PACKET;
	sll_bind.sll_ifindex = ifindex;
	sll_bind.sll_protocol = htons(ETH_P_ALL);

	ret = bind(sock, (struct sockaddr *) &sll_bind, sizeof(sll_bind));
	if (ret < 0) {
		WARN(CMBSTR3("bind %",IFNAMSIZ,"s: %s"),
			ifreq.ifr_name, strerror(errno));
		close(sock);
		return ret;
	}

	nd->ifname = ifname;
	nd->ifindex = ifindex;
	nd->net_sock = sock;

	/* FILTER: completely optional if you don't mind your machine grinding
	 * to a halt due to an inane amount of traffic. Only warn on errors.
	 * */
	{
#ifdef DEBUG
		WARN("filter start");
		print_fcode(&fcode);
#endif

		/* obtain ip & netmask of named IF */
		int inet_sock = socket(AF_INET, SOCK_STREAM, 0);

		struct ifreq req;
		memset(&req, 0, sizeof(req));
		strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

		struct sockaddr_in *addr = (struct sockaddr_in *)&(req.ifr_addr);

		ret = ioctl(inet_sock, SIOCGIFADDR, &req);

		if (ret < 0) {
			if (errno == EADDRNOTAVAIL) {
				WARN(CMBSTR3("interface %", IFNAMSIZ,
					"s does not have an address"),
					req.ifr_name);
				return 1;
			} else {
				WARN("SIOCGIFADDR fail: %s", strerror(errno));
			}
			return 1;
		}

		uint32_t net_ip = ntohl(addr->sin_addr.s_addr);

		ret = ioctl(inet_sock, SIOCGIFNETMASK, &req);
		if (ret < 0) {
			WARN("SIOCGIFNETMASK fail: %s", strerror(errno));
			return 1;
		}
		uint32_t net_sub = ntohl(addr->sin_addr.s_addr);

		uint32_t net_sub_ip = net_sub & net_ip;

		net_filter[FILT_IP_CHECK].k = net_sub_ip;
		net_filter[FILT_SUB_CHECK].k = net_sub;

#ifdef DEBUG
		WARN("Populated:");
		print_fcode(&fcode);
#endif

		ret = setsockopt(nd->net_sock, SOL_SOCKET, SO_ATTACH_FILTER,
				&fcode, sizeof(fcode));

		if (ret < 0) {
			WARN("filter failed %s", strerror(errno));
			return 1;
		}
	}
	return 0;
}
