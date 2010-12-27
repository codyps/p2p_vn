#ifndef DARRAY_H_
#define DARRAY_H_

#include <stdbool.h>

#define DA_CHECK_AND_REALLOC(mem_base, mem_sz, new_elem_ct)       \
	({ bool fail;                                             \
	if ((new_elem_ct) > (mem_sz)) {                           \
		typeof(mem_sz) attempt_sz = 2 * (mem_sz) + 8;     \
		typeof(mem_base) new_mem_base = realloc(mem_base, \
			sizeof(*(mem_base)) * attempt_sz);        \
		if (!new_mem_base) {                              \
			fail = true;                              \
		} else {                                          \
			mem_base = new_mem_base;                  \
			mem_sz = attempt_sz;                      \
			fail = false;                             \
		}                                                 \
	} else {                                                  \
		fail = false;                                     \
	}                                                         \
	fail; })


#define DA_REMOVE(base_p, ct, rem_p) do {                                     \
	(ct) --;                                                              \
	size_t ct_ahead = (rem_p) - (base_p);                                 \
	size_t ct_to_end = (ct) - ct_ahead;                                   \
	memmove((rem_p), (rem_p)+1, ct_to_end * sizeof(*(base_p)));           \
} while (0)

#define DA_INIT(base_p, ct, mem, init_sz) ({              \
	bool fail;                                        \
	(base_p) = malloc(sizeof(*(base_p)) * (init_sz)); \
	if (!(base_p)) {                                  \
		fail = true;                              \
	} else {                                          \
		(ct) = 0;                                 \
		(mem) = (init_sz);                        \
		fail = false;                             \
	}                                                 \
	fail; })
#endif
