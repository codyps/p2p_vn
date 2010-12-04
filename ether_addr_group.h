#ifndef ETHER_ADDR_TREE_H_
#define ETHER_ADDR_TREE_H_

typedef struct ether_addr_group {


} eag_t;

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


#endif
