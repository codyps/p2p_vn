#ifndef SVECT_H_
#define SVECT_H_

#include <stdbool.h>

#define DA_DEF_TYPE(type)    \
	struct da_##type {   \
		size_t ct;   \
		size_t mem;  \
		type *items; \
	}

#define DA_INIT_MEM 8

#define DA_DEF_FUNC(name, type, cmp, fattr) \
	fattr DA_DEF_INIT(type)             \
	fattr DA_DEF_REMOVE(type, cmp)      \
	fattr DA_DEF_INSERT(type, cmp)      \
	fattr DA_DEF_SEARCH(type, cmp)      \

#define da_t(type) struct da_##type

/* the parameter `name` needs to embody both the cmp and type. */
#define da_remove(name) da_remove_##name
#define da_init(name) da_init_##name
#define da_search(name) da_search_##name
#define da_insert(name) da_insert_##name

#define DA_DEF_INIT(name, type)                                    \
	int da_init(name)(da_t(type) *da) {                        \
		da->ct = 0;                                        \
		da->mem = 8;                                       \
		da->items = malloc(sizeof(*da->items) * da->mem);  \
		if (!da->items)                                    \
			return -1;                                 \
		return 0;                                          \
	}

#define DEF_BSEARCH(name, type, cmp)				\
	type *bsearch_##name(type const *key, type const *base,	\
			size_t nmemb) {				\
		size_t l, u, idx;				\
		type const *p;					\
		int comparison;					\
								\
		l = 0;						\
		u = nmemb;					\
		while (l < u) {					\
			idx = (l + u) / 2;			\
			p = base + idx;				\
			comparison = cmp(key, p);		\
			if (comparison < 0)			\
				u = idx;			\
			else if (comparison > 0)		\
				l = idx + 1;			\
			else					\
				return (type *)p;		\
		}						\
		return NULL;					\
	}

#define DA_DEF_REMOVE(name, type, cmp)                                \
	int da_remove(name)(type *base, type *key) {                  \
		type *found = bsearch(key, base, sizeof(*base), cmp); \
	}\

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
