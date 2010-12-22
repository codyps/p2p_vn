#ifndef PEER_PACKET_H_
#define PEER_PACKET_H_

#include <stdint.h>

#define __packed __attribute__((packed))
#define __aligned __attribute__((aligned))

typedef uint64_t pkt_ts_ms_t;
typedef uint32_t pkt_rtt_us_t;

enum pkt_type {
	/** required packet types **/
	PT_DATA = 0xabcd,
	/* both the join and part (prof. calls it "leave") have the same
	 * number and are distinguished by length */
	PT_JOIN_PART = 0xab01,
	PT_JOIN = 0xab01,
	PT_PART = 0xab01,

	/* spec indicates that upon reciept, proxy should die */
	PT_QUIT = 0xab03,

#if 0
	/* link state */
	PT_LINK = 0xabaa, /* the old format, flooded */
#endif

	/* the new format, only sent to direct peers */
	PT_LINK_GRAPH = 0xabac,

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

	/* rtt will respond to saturated links by decreasing, meaning we'll
	 * begin to schedule packets over other paths, making explicit
	 * bandwidth measurment moot */
	PT_BWPROBE_REQ = 0xab35,
	PT_BWPROBE_RESP = 0xab36
} __packed __aligned;

enum pkt_len {
	PL_U64 = sizeof(uint64_t),
	PL_U32 = sizeof(uint32_t),
	PL_U16 = sizeof(uint16_t),
	PL_U8  = sizeof(uint8_t),

	_PL_HOST = PL_U32 + PL_U16 + PL_U8 * 6,
	PL_HEADER = PL_U16 * 2,
	PL_JOIN = _PL_HOST,
	PL_LEAVE = _PL_HOST + PL_U8,
	PL_QUIT = 0,
	PL_PROBE_REQ = PL_U16,
	PL_PROBE_RESP = PL_U16,


#if 0
	PL_LINK_STATIC = 2 + _PL_HOST + 1,
	PL_NEIGHBOR = _PL_HOST + 4 + 8,
#endif

	PL_LINK_GRAPH_STATIC = PL_U16 + _PL_HOST,
	PL_EDGE = PL_U32 + PL_U64 + _PL_HOST * 2
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

#if 0 /* out dated */
struct _pkt_neighbor {
	struct _pkt_ipv4_host host;
	uint32_t rtt_us;
	uint64_t ts_ms;
} __packed;

/* link packet "old" */
struct pkt_link {
	uint16_t neighbor_ct;
	struct _pkt_ipv4_host vec_src_host;

	/* Ignored, set to zero */
	uint8_t ttl;

	struct _pkt_neighbor neighbors[];
} __packed __aligned;
#endif

struct _pkt_edge {
	struct _pkt_ipv4_host src;
	struct _pkt_ipv4_host dst;
	uint32_t rtt_us;
	uint64_t ts_ms;
} __packed;

/* link packet "new" */
struct pkt_link_graph {
	/* ignore, calculate via packet len */
	uint16_t edge_ct;
	struct _pkt_ipv4_host vec_src_host;

	struct _pkt_edge edges[];
} __packed __aligned;

struct pkt_probe_req {
	uint16_t seq_num;
} __packed __aligned;

struct pkt_probe_resp {
	uint16_t seq_num;
} __packed __aligned;

#endif
