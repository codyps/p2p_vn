#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

typedef struct ether_addr_s {
	uint8_t addr[ETH_ALEN];
} ether_addr_t;

#define tv_ms(tv) ((tv)->tv_sec * 1000 + (tv)->tv_usec / 1000)
#define tv_us(tv) ((tv)->tv_sec * 1000000 + (tv)->tv_usec )

typedef uint32_t __be32;
typedef uint16_t __be16;

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

#endif
