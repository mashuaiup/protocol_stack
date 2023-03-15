/*ms:
	创建一个arp双向链表
 */
#ifndef __NG_ARP_H__
#define __NG_ARP_H__

#include <rte_ether.h>


#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1

//双向链表的增加,头插法
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)

//双向链表的删除
#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)


struct arp_entry {

	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];//mac地址

	uint8_t type;
	// 
	struct arp_entry *next;
	struct arp_entry *prev;
};

struct arp_table {
	struct arp_entry *entries;
	int count;
};

//单例模式.
static struct  arp_table *arpt = NULL;

static struct  arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}

	return arpt;

}

//从arp表里面查找ip对应的mac地址
static uint8_t* ng_get_dst_macaddr(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries;iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}

	return NULL;
}


#endif


