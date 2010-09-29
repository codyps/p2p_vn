#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

int main(void)
{
	int r = socket(AF_PACKET, SOCK_RAW, 0);
	if (r < 0)
		perror("packet socket:");
	return r;
}
