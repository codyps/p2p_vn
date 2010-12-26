#ifndef DARRAY_H_
#define DARRAY_H_

#include <stdbool.h>

#define CHECK_AND_REALLOC(mem_base, mem_sz, new_elem_ct)          \
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

#endif
