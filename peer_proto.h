#ifndef PEER_PACKET_H_
#define PEER_PACKET_H_

#include <stdint.h>

#define __packed __attribute__((packed,aligned(__BIGGEST_ALIGNMENT__))

enum p_type_e {
	/** required packet types **/
	PT_DATA = 0xabcd,
	/* both the join and part (prof. calls it "leave") have the same
	 * number and are distinguished by length */
	PT_JOIN_PART = 0xab01,
	/* it is unclear what differentiates this from part */
	PT_QUIT = 0xab03,
	/* link state */
	PT_LINK = 0xabaa,
	PT_PROBE_REQ = 0xab34,
	PT_PROBE_RESP = 0xab35,

	/** optional packet types **/
	/* "proxy public key" */
	PT_PUBKEY = 0xab21,
	PT_DATA_SIGNED = 0xabc1,

	/* "proxy secret key": i really hope this isn't the key itself.
	 * sending that over the network would be supremely incompetent. */
	PT_SECKEY = 0xab22,

	/* this appears to indicate that the type and length data won't be
	 * encrypted, which is very, very[, very,...] bad */
	PT_DATA_ENC = 0xabc2,
	PT_LINK_ENC = 0xabab,

	PT_BWPROBE_REQ = 0xab35,
	PT_BWPROBE_RESP = 0xab36
} __packed;

struct pkt_header {
	uint16_t type;
	uint16_t len;
} __packed;

#if 0
/* Not supported by gcc. damn it. */
struct pkt_data {
	uint8_t data [];
} __packed
#endif

struct ipv4_host {
	uint8_t ip[4];
	uint16_t port;
	uint8_t mac[6];
} __packed;

struct pkt_join {
	struct ipv4_host local;
} __packed;

struct pkt_part {
	/* XXX: unclear how to fill this. also: OH GOD ALIGNMENT. */
	uint8_t ttl;
	struct ipv4_host local;
} __packed;

struct pkt_quit {
} __packed;

struct neighbor {
	struct ipv4_host host;
	uint32_t rtt_us;  /* rtt in us */
	uint64_t ts_ms; /* timestamp in ms */
} __packed;

struct pkt_link {
	uint16_t neighbor_ct;
	struct ipv4_host local;

	/* XXX: it is unclear as to why this is needed, as the periodic
	 * sending of link state packets means we are no longer doing a
	 * full-flood. Cycles are made impossible because pkts aren't sent
	 * in response to received packets. */
	uint8_t ttl;
	struct neighbor neighbors[];
} __packed;

struct pkt_probe_req {
	uint16_t seq_num;
} __packed;

struct pkt_probe_resp {
	uint16_t seq_num;
} __packed;

/* Note that "pkt_data" is absent due to it's internals being completely
 * unstructured */
struct pkt_full {
	struct pkt_header header;
	union {
		//struct pkt_data data;
		//uint8_t data[];
		struct pkt_join join;
		struct pkt_part part;
		struct pkt_quit quit;
		struct pkt_link link;
		struct pkt_probe_req preq;
		struct pkt_probe_resp presp;
	};
} __packed;

#endif
