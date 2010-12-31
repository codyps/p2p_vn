#ifndef SVECT_H_
#define SVECT_H_

#include <stdbool.h>
#include "darray.h"
#include "stdparam.h"

#define SV_DEF_FUNC(name, type, cmp, fattr) \
	fattr DEF_BSEARCH(name, type, cmp)  \
	fattr DA_DEF_INIT(type)             \
	fattr SV_DEF_REMOVE(type, cmp)      \
	fattr SV_DEF_INSERT(type, cmp)      \
	fattr SV_DEF_SEARCH(type, cmp)

/* the parameter `name` needs to embody both the cmp and type. */
#define sv_remove(name) sv_remove_##name
#define sv_search(name) sv_search_##name
#define sv_insert(name) sv_insert_##name

#define SV_DEF_REMOVE(name, type, cmp)                                \
	int sv_remove(name)(da_t(, type *key) {                  \
		type *found = bsearch_##name(key, base, ); \
	}\

#endif
