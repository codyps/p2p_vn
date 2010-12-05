#ifndef ETHER_ADDR_TREE_H_
#define ETHER_ADDR_TREE_H_

#include "routing.h"

typedef struct ether_addr_group {
	struct eth_node* head;
} eag_t;

typedef struct eth_node {
	ether_addr_t *mac;		
	struct eth_node* link[2];
} *node_t;

/* all functions: negative return value on error */
int eag_init(eag_t *eag);

/* returns 1 if `mac' already exsisted in the tree,
 * otherwise 0 
 *
 * Will not add duplicate mac addr's to the tree */
int eag_insert(eag_t *eag, ether_addr_t mac);

/* returns 1 if `mac' not in the tree,
 * otherwise 0 */
int eag_remove(eag_t *eag, ether_addr_t mac);

int mac_cmp(ether_addr_t a1, ether_addr_t a2);	

#endif
