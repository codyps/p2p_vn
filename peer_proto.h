#ifndef PEER_PACKET_H_
#define PEER_PACKET_H_

#include <stdint.h>

#define __packed __attribute__((packed))
#define __aligned __attribute__((aligned))

enum pkt_type {
	/** required packet types **/
	PT_DATA = 0xabcd,
	/* both the join and part (prof. calls it "leave") have the same
	 * number and are distinguished by length */
	PT_JOIN_PART = 0xab01,
	PT_JOIN = 0xab01,
	PT_PART = 0xab01,

	/* it is unclear what differentiates this from part */
	PT_QUIT = 0xab03,
	/* link state */
	PT_LINK = 0xabaa,

	/* probes */
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
} __packed __aligned;

enum pkt_len {
	PL_HEADER = 4,
	PL_JOIN = 12,
	PL_LEAVE = 13,
	PL_QUIT = 0,
	PL_PROBE_REQ = 2,
	PL_PROBE_RESP = 2,

	_PL_HOST = 12,

	PL_LINK_STATIC = 2 + _PL_HOST + 1,
	PL_NEIGHBOR = _PL_HOST + 4 + 8,
} __packed __aligned;

struct pkt_header {
	uint16_t type;
	uint16_t len;
} __packed __aligned;

#if 0
/* Not supported by gcc. damn it. */
struct pkt_data {
	uint8_t data [];
} __packed
#endif

struct _pkt_ipv4_host {
	uint32_t ip;
	uint16_t port;
	uint8_t mac[6];
} __packed;

struct pkt_join {
	struct _pkt_ipv4_host joining_host;
} __packed __aligned;

struct pkt_part {
	/* XXX: unclear how to fill this. also: OH GOD ALIGNMENT. */
	uint8_t ttl;
	struct _pkt_ipv4_host parting_host;
} __packed __aligned;

#if 0
struct pkt_quit {
} __packed;
#endif

struct _pkt_neighbor {
	struct _pkt_ipv4_host host;
	uint32_t rtt_us; /* rtt in us */

	/* PROTO: why the hell this got put here I'll never know,
	 * we really want it in pkt_link to use as a sequence
	 * number.
	 */
	uint64_t ts_ms;
} __packed;

struct pkt_link {
	uint16_t neighbor_ct;
	struct _pkt_ipv4_host vec_src_host;

	/* Ignored, set to zero */
	uint8_t ttl;

	struct _pkt_neighbor neighbors[];
} __packed __aligned;

struct pkt_probe_req {
	uint16_t seq_num;
} __packed __aligned;

struct pkt_probe_resp {
	uint16_t seq_num;
} __packed __aligned;

#endif
