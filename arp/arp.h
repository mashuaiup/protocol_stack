#ifndef __ARP__
#define __ARP__
#include <rte_ether.h>
#include <rte_timer.h>
#include "define.h"
#include "std.h"
#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1
// extern uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];
struct arp_entry {

	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];

	uint8_t type;
	// 
	struct arp_entry *next;
	struct arp_entry *prev;
	
};
struct arp_table {
	struct arp_entry *entries;
	int count;
	pthread_spinlock_t spinlock;
};
typedef struct arp_s{
	uint32_t gLocalIp;
	uint8_t  gSrcMac[RTE_ETHER_ADDR_LEN];
	struct   arp_table* arp_tb;
}arp_arg_t;

// struct  arp_table *arp_table_instance(void);
uint8_t* ng_get_dst_macaddr(uint32_t dip, struct arp_table *table);
int ng_arp_entry_insert(uint32_t ip, uint8_t *mac, arp_arg_t *arp_st);
int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *src_mac, uint8_t *dst_mac, uint32_t sip, uint32_t dip);
struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *src_mac, uint8_t *dst_mac, uint32_t sip, uint32_t dip);
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg);
void arp_process(struct rte_mbuf *arpmbuf, struct rte_mempool *mbuf_pool, arp_arg_t *arp_st, struct inout_ring* ioa_ring);
void arp_out(struct rte_mempool *mbuf_pool, struct inout_ring *ioa_ring, arp_arg_t *arp_st);
// void handle_arp(struct rte_mbuf *mbuf, struct rte_mempool *mbuf_pool);
#endif