#include <stdlib.h>
#include "ether_addr_group.h"
#include "routing.h"

/* all functions: negative return value on error */
int eag_init(eag_t *eag) {
	eag->head = malloc(sizeof(struct eth_node));
//	eag->head->mac = NULL;
//	eag->head->link[0] = NULL;
//	eag->head->link[1] = NULL;
}

 node_t create_node(ether_addr_t mac) {
	node_t new_node;
	new_node = malloc(sizeof(struct eth_node));
	new_node->mac = mac;
	new_node->link[0] = NULL;
	new_node->link[1] = NULL;
	return new_node;
 }

/* returns 1 if `mac' already exsisted in the tree,
 * otherwise 0 
 *
 * Will not add duplicate mac addr's to the tree */
int eag_insert(eag_t *eag, ether_addr_t mac) {
	
	if(eag->head == NULL) {
		eag->head = create_node(mac);
		return 0;
	}

	node_t temp = eag->head;
	int c;
	
	for( ; ; ) {
		c = mac_cmp(mac, temp->mac);
		if(c != 0 && c != 1) {
			return 1;
		} else if(temp->link[c] == NULL) {
			temp->link[c] = create_node(mac);
			return 0;
		}
		temp = temp->link[c];
	}
	
	return -1;
}

/* returns 1 if `mac' not in the tree,
 * otherwise 0 */
int eag_remove(eag_t *eag, ether_addr_t mac) {
	/*if(eag->head == NULL) {
		return 1;
	}
	
	node_t temp = eag->head;
	int c;
	for( ; ; ) {
	*/
	if ( eag->head != NULL ) {
    node_t head = {0};
    node_t it = head;
    node_t p, f = NULL;
    int dir = 1;
      it->link[1] = eag->head;
      while ( it->link[dir] != NULL ) {
      p = it;
       it = it->link[dir];
       dir = mac_cmp(it->mac, mac);
 
       if ( dir == 2 )
         f = it;
     }
 
     if ( f != NULL ) {
       f->mac = it->mac;
       p->link[p->link[1] == it] = it->link[it->link[0] == NULL];
       free ( it );
     }
 
     eag->head = head->link[1];
   }
 
   return 1;

	
}
/*return 2 if equal, 0 less, 1 greater*/
int mac_cmp(ether_addr_t a1, ether_addr_t a2) {
	int x;
	for(x = 0; x < ETH_ALEN; x++) {
		if(a1[x] > a2[x]) {
			return 1;
		}
		if( a1[x] < a2[x]) {
			return -1;
		}
	}
	return 0;
}
