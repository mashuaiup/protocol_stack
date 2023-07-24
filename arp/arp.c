#include "arp.h"
#include <rte_mbuf.h>
#include <rte_arp.h>
#include "std.h"
#include <rte_ring.h>
#include <arpa/inet.h>
#include <rte_ip.h>
#include <rte_malloc.h>


/* struct  arp_table *arpt = NULL;
struct  arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));

		pthread_spin_init(&arpt->spinlock, PTHREAD_PROCESS_SHARED);
	}
	return arpt;
} */

uint8_t* ng_get_dst_macaddr(uint32_t dip, struct arp_table *table) {

	struct arp_entry *iter;
	// struct arp_table *table = arp_table_instance();

	int count = table->count;
	
	for (iter = table->entries; count-- != 0 && iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}
	return NULL;
}

int ng_arp_entry_insert(uint32_t ip, uint8_t *mac, arp_arg_t *arp_st) {

	// struct arp_table *table = arp_table_instance();

	uint8_t *hwaddr = ng_get_dst_macaddr(ip, arp_st->arp_tb);
	if (hwaddr == NULL) {

		struct arp_entry *entry = (struct arp_entry *)rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
		if (entry) {
			memset(entry, 0, sizeof(struct arp_entry));

			entry->ip = ip;
			rte_memcpy(entry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			entry->type = 0;

			// pthread_spin_lock(&arp_st->arp_tb->spinlock);
			LL_ADD(entry, arp_st->arp_tb->entries);
			arp_st->arp_tb->count ++;
			// pthread_spin_unlock(&arp_st->arp_tb->spinlock);
			
		}

		return 1; //
	}

	return 0;
}

int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode,uint8_t *src_mac, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
		uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
		rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return 0;

}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode,uint8_t *src_mac, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data, opcode, src_mac, dst_mac, sip, dip);

	return mbuf;
}

//arg应该是一个结构体指针
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	   void *arg) {

	struct stack_arg *sat = (struct stack_arg *)arg;
	arp_arg_t* arp_st =(arp_arg_t *)sat->arp_arg;
	struct inout_ring *ring = sat->io_ring;

	int i = 0;
	for (i = 1;i <= 254;i ++) {

		uint32_t dstip = (arp_st->gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));

		struct rte_mbuf *arpbuf = NULL;
		uint8_t *dstmac = ng_get_dst_macaddr(dstip, arp_st->arp_tb);
		if (dstmac == NULL) {
			uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};;
			arpbuf = ng_send_arp(sat->mbuf_pool, RTE_ARP_OP_REQUEST, arp_st->gSrcMac, gDefaultArpMac, arp_st->gLocalIp, dstip);
		
		} else {

			arpbuf = ng_send_arp(sat->mbuf_pool, RTE_ARP_OP_REQUEST, arp_st->gSrcMac, dstmac, arp_st->gLocalIp, dstip);
		}

		//rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		//rte_pktmbuf_free(arpbuf);
		rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
	}
	
}

void print_list_value(struct arp_table *table){
	printf("查看现在的arp表内容\n");
	struct arp_entry *iter;
	int count = table->count;
	for (iter = table->entries; count-- != 0 && iter != NULL; iter = iter->next) {
		struct in_addr addr;
		addr.s_addr = iter->ip;
		printf("ip:%s ->",inet_ntoa(addr));
		char buf[RTE_ETHER_ADDR_FMT_SIZE];
		rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (const struct rte_ether_addr *)iter->hwaddr);
		printf("mac:%s\n",buf);
	}

}


void arp_process(struct rte_mbuf *arpmbuf, struct rte_mempool *mbuf_pool, arp_arg_t *arp_st, struct inout_ring *ioa_ring){

	struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(arpmbuf, 
		struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

	if (ahdr->arp_data.arp_tip == arp_st->gLocalIp) {

		struct in_addr addr;
		addr.s_addr = ahdr->arp_data.arp_sip;
		printf("arp ---> src: %s ", inet_ntoa(addr));

		if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {

			printf("arp --> request\n");

			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, arp_st->gSrcMac, ahdr->arp_data.arp_sha.addr_bytes, 
				ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

			// rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
			int num = rte_ring_mp_enqueue_burst(ioa_ring->out, (void**)&arpbuf, 1, NULL);
			if(num < 1){
				printf("arp协议数据包发送失败\n");
			}
			rte_pktmbuf_free(arpbuf);

		} else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {

			printf("arp --> reply\n");

			struct arp_table *table = arp_st->arp_tb;

			uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip, table);

			print_list_value(table);

			if (hwaddr == NULL) {
				struct arp_entry *entry = (struct arp_entry *)rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
				if (entry) {
					memset(entry, 0, sizeof(struct arp_entry));

					entry->ip = ahdr->arp_data.arp_sip;
					rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
					entry->type = 0;
					
					LL_ADD(entry, table->entries);
					table->count ++;
				}
				print_list_value(table);
			}
			rte_pktmbuf_free(arpmbuf);
		}
	} 
}

void arp_out(struct rte_mempool *mbuf_pool, struct inout_ring *ioa_ring, arp_arg_t *arp_st){
	struct rte_mbuf *packets[BURST_SIZE];
	unsigned nb_tx = rte_ring_sc_dequeue_burst(ioa_ring->arp_ring, (void**)packets, BURST_SIZE, NULL);
	if (nb_tx > 0) {
		unsigned i = 0;
		printf("arp 3\n");
		for (i = 0;i < nb_tx;i ++) {
			//fill srcmac dstmac and
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(packets[i], struct rte_ether_hdr*);
			struct in_addr addr;
			uint8_t *dstmac = NULL;
			if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(packets[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
				addr.s_addr = iphdr->dst_addr;
			}
			dstmac = ng_get_dst_macaddr(addr.s_addr, arp_st->arp_tb);
			if(dstmac == NULL){
				//send arp requeset and copy packet into arp_ring
				uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
				struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, arp_st->gSrcMac,gDefaultArpMac, 
				arp_st->gLocalIp, addr.s_addr);
				rte_ring_mp_enqueue_burst(ioa_ring->out, (void**)&arpbuf, 1, NULL);
				//copy
				int num = rte_ring_sp_enqueue_burst(ioa_ring->arp_ring, (void **)&packets[i], 1, NULL);
			}else{
				//send packet into out_ring
				rte_memcpy(ehdr->s_addr.addr_bytes, arp_st->gSrcMac, RTE_ETHER_ADDR_LEN);
				rte_memcpy(ehdr->d_addr.addr_bytes, dstmac         , RTE_ETHER_ADDR_LEN);
				int num = rte_ring_mp_enqueue_burst(ioa_ring->out, (void **)&packets[i], 1, NULL);
				if(num < 0){
					printf("arp层复制数据至ring->out失败\n");
				}
			}
			rte_pktmbuf_free(packets[i]);
		}
	}
}