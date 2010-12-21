#ifndef DEBUG_H_
#define DEBUG_H_
#include <stdio.h>
#include <errno.h>
#include "routing.h"

extern int debug;

void mac_address_print(ether_addr_t *mac, FILE *out);
__attribute__((format(printf,5,6)))
void error_at_line(int status, int errnum, const char *filename,
                   unsigned int linenum, const char *format, ...);

#define DP_WARN(dp, ...) do { \
	mac_address_print(DP_MAC(dp), stderr); \
	fputs(" : ", stderr);                       \
	WARN(__VA_ARGS__); \
} while(0)

#define H_WARN(_rt_h, ...) do { \
	mac_address_print(&((_rt_h)->host->mac), stderr); \
	fputs(" : ", stderr);                       \
	WARN(__VA_ARGS__); \
} while(0)

#define EDGE_DEBUG(src_h, dst_h, ...) do {           \
	if (debug) {                                 \
		EDGE_WARN(src_h, dst_h, __VA_ARGS__);\
	}                                            \
} while(0)

#define EDGE_WARN(src_h, dst_h, ...) do {           \
	mac_address_print(&((src_h)->mac), stderr); \
	fputs(" -> ", stderr);                      \
	mac_address_print(&((dst_h)->mac), stderr); \
	fputs(" : ", stderr);                       \
	WARN(__VA_ARGS__);                          \
} while(0)


#define H_DEBUG(dp, ...) do {     \
	if (debug) {               \
		H_WARN(dp, __VA_ARGS__); \
	}                          \
} while(0)

#define DP_DEBUG(dp, ...) do {     \
	if (debug) {               \
		DP_WARN(dp, __VA_ARGS__); \
	}                          \
} while(0)

#define DEBUG(...) do {            \
	if (debug) {               \
		WARN(__VA_ARGS__); \
	}                          \
} while(0)

#define WARNe(errnum, ...) error_at_line(0, errnum, __FILE__, __LINE__, __VA_ARGS__)
#define WARN(...) do {             \
	WARNe(errno, __VA_ARGS__); \
	errno = 0;                 \
} while(0)

#define DIEe(errnum, ...) error_at_line(1, errnum, __FILE__, __LINE__, __VA_ARGS__)
#define DIE(...) do {             \
	DIEe(errno, __VA_ARGS__); \
	errno = 0;                \
} while(0)

#endif
