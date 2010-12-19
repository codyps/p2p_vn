#ifndef DEBUG_H_
#define DEBUG_H_
#include <stdio.h>
#include <errno.h>
#include "routing.h"

void mac_address_print(ether_addr_t mac, FILE *out);
__attribute__((format(printf,5,6)))
void error_at_line(int status, int errnum, const char *filename,
                   unsigned int linenum, const char *format, ...);

#define DP_WARN(dp, ...) do { \
	mac_address_print((dp)->remote_mac, stderr); \
	WARN(__VA_ARGS__); \
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
