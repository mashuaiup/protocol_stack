#include <arp.h>

int ng_encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);
	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(2);
	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	return 0;
}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;
	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data, dst_mac, sip, dip);
	return mbuf;
}


void handle_arp(struct rte_mbuf *mbuf, struct rte_mempool *mbuf_pool){
	struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbuf, 
					struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
	struct in_addr addr;
	addr.s_addr = ahdr->arp_data.arp_tip;//获取arp报文中的目的IP地址
	printf("arp ---> src: %s ", inet_ntoa(addr));
	addr.s_addr = gLocalIp;
	printf("local: %s \n", inet_ntoa(addr));
	if (ahdr->arp_data.arp_tip == gLocalIp) {//如果这个目的IP地址就是本机的IP地址（都需要是网络字节序）
		struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, ahdr->arp_data.arp_sha.addr_bytes, 
			ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
		rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		rte_pktmbuf_free(arpbuf);
		rte_pktmbuf_free(mbuf);
	}
}