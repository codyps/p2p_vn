#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <arpa/inet.h>

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

/* presently this does "\(not ip \) or \( ip src 192.168.0.1 \)" */
struct sock_filter sf[] {
	/* Load h_proto in ethernet header */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsetof(struct ethhdr, h_proto)),

	/* Check for IP packets. T = next, F = done succ. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 1, 4),

	/* load ip src */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ETH_HLEN + offsetof(struct iphdr, saddr)),

	/* is ipsrc == the filtered address? */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 2),

	/* accept entire packet */
	BPF_STMT(BPF_RET | BPF_K, -1),

	/* reject packet */
	BPF_STMT(BPF_RET | BPF_K, 0)
};

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <netdev>\n", argc?argv[0]:"ifalias");
		return -2;
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);

	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, argv[1], sizeof(req.ifr_name));

	struct sockaddr_in *addr = (struct sockaddr_in *)&(req.ifr_addr);


	int ret = ioctl(sock, SIOCGIFADDR, &req);

	if (ret < 0) {
		fprintf(stderr, "SIOCGIFADDR failed: %s\n", strerror(errno));
		return -1;
	}

	char ipbuf[256];
	if (!inet_ntop(AF_INET, &addr->sin_addr, ipbuf, sizeof(ipbuf))) {
		fprintf(stderr, "inet_ntop fail: %s\n", strerror(errno));
		return -1;
	}

	printf("%s = %s = 0x%x\n", argv[1], ipbuf, ntohl(addr->sin_addr.s_addr));

	return 0;
}
