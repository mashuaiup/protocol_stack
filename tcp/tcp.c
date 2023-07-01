#include<tcp.h>

void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received){
	//ethdr
	struct rte_ether_hdr * ethdr = (struct rte_ether_hdr *)pkt;
	rte_memcpy(ethdr->s_addr.addr_bytes, ethdr_received->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	rte_memcpy(ethdr->d_addr.addr_bytes, ethdr_received->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	//iphdr
	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ethdr + 1);
	struct rte_ipv4_hdr *iphdr_received = (struct rte_ipv4_hdr *)(ethdr_received + 1);
	iphdr->version_ihl = 0x45;
	iphdr->type_of_service = 0;
	iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
	printf("iphdr->total_length:%04x\n", iphdr->total_length);
	iphdr->packet_id =  0;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live =64;
	iphdr->next_proto_id = IPPROTO_TCP;
	iphdr->src_addr = iphdr_received->dst_addr;
	iphdr->dst_addr = iphdr_received->src_addr;
	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
	//tcphdr
	struct rte_tcp_hdr * tcphdr =  (struct rte_tcp_hdr *)(iphdr+ 1);
	struct rte_tcp_hdr * tcphdr_received =  (struct rte_tcp_hdr *)(iphdr_received + 1);
	tcphdr->src_port = tcphdr_received->dst_port;
	tcphdr->dst_port = tcphdr_received->src_port;
	tcphdr->sent_seq = tcp_stream_item->send_sqe;
	tcphdr->recv_ack = htonl(ntohl(tcphdr_received->sent_seq) + 1); //暂时没能理解
	tcp_stream_item->recv_sqe = tcphdr->recv_ack;
	tcphdr->data_off = 0x50;
	tcphdr->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
	tcphdr->rx_win = TCP_INITIAL_WINDOW;
	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, (const void *)tcphdr);
}