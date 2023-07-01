#include<udp.h>

int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {
	// encode 
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
	// 3 udphdr 
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);
	rte_memcpy((uint8_t*)(udp + 1), data, udplen);
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));
	addr.s_addr = gDstIp;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));
	return 0;
}
struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {
	// mempool --> mbuf
	const unsigned total_len = length + 42;
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);//从内存池中获取一个新的内存块
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ng_encode_udp_pkt(pktdata, data, total_len);
	return mbuf;
}
void handle_udp(struct rte_mbuf * mbuf, struct rte_mempool* mbuf_pool){
	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
	rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
	rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));
	rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
	rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

	uint16_t length = ntohs(udphdr->dgram_len);
	*((char*)udphdr + length) = '\0';
	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
	addr.s_addr = iphdr->dst_addr;
	printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), 
		(char *)(udphdr+1));
	struct rte_mbuf *txbuf = ng_send_udp(mbuf_pool, (uint8_t *)(udphdr+1), length);
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
				rte_pktmbuf_free(txbuf);
	rte_pktmbuf_free(mbuf);
}