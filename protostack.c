#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <time.h>
#include <stdio.h>
#include "protostack.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"

#define ENABLE_SEND		1
#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32
#define TCP_MAX_SQE 4294967296
#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))//转换成网络字节序
uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 35, 199);
uint32_t gSrcIp; //
uint32_t gDstIp;
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
uint16_t gSrcPort;
uint16_t gDstPort;
#endif
int gDpdkPortId = 0;
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static  tcp_stream_table* get_stream_table_instance(void){
	if(!stream_table){
		stream_table = rte_malloc("stream_table", sizeof(tcp_stream_table), 0);
		if(stream_table==NULL){
			rte_exit(EXIT_FAILURE, "rte_malloc error!");
		}
		memset(stream_table, 0 ,sizeof(tcp_stream_table));
	}
	return stream_table;
}

static tcp_stream * query_stream(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
	tcp_stream_table *list = get_stream_table_instance();
	while(list->stream_item){
		if(list->stream_item->sip == sip && list->stream_item->dip == dip && list->stream_item->sport == sport && list->stream_item->dport == dport){
			return list->stream_item;
		}
	}
	return NULL;
}

static tcp_stream * create_connect_stream(struct rte_ipv4_hdr *iphdr, struct rte_tcp_hdr* tcphdr){	
	tcp_stream * stream = rte_malloc("stream", sizeof(tcp_stream), 0);
	stream->sip = iphdr->src_addr;
	stream->dip = iphdr->dst_addr;

	stream->sport = tcphdr->src_port;
	stream->dport = tcphdr->dst_port;
	stream->proto = iphdr->next_proto_id;
	srand((unsigned)time(NULL));
	stream->send_sqe = rand() % TCP_MAX_SQE;
	printf("其中stream->send_sqe:%d",stream->send_sqe);
	stream->status = NG_TCP_TCP_STATUS_LISTEN;
	stream->pre = NULL;
	stream->next = NULL;
	return stream;
}

static int handle_listen(tcp_stream *tcp_stream_item, struct rte_mempool * mbuf_pool,struct rte_ether_hdr *ehdr, struct rte_ipv4_hdr *iphdr, struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags == RTE_TCP_SYN_FLAG){
		uint32_t sip = iphdr->src_addr;
		printf("客户端%d发来连接请求\n", sip);
		//申请mbuf
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
		if(mbuf == NULL){
			rte_exit(EXIT_FAILURE,"alloc error!\n");
		} 
		//1、构造报文 
		uint32_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
		mbuf->data_len = total_len;
		mbuf->pkt_len = total_len;
		uint8_t *pktbuf = rte_pktmbuf_mtod(mbuf, uint8_t*);
		ng_encode_tcp_pkt(pktbuf, tcp_stream_item, ehdr);
		//2、通过tx_brust传送出去 
		rte_eth_tx_burst(gDpdkPortId, 0, &mbuf, 1);
		rte_pktmbuf_free(mbuf);
		//3、将状态转换成syn_received
		tcp_stream_item->status = NG_TCP_TCP_STATUS_SYN_RECEIVED;		
	}
	return 0;
}

static void handle_syn_received(tcp_stream *tcp_stream_item,struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags == RTE_TCP_SYN_FLAG){
		printf("再次收到请求报文,连接失败\n");
	}else{
		printf("连接成功\n");
	}
	tcp_stream_item->status = NG_TCP_TCP_STATUS_ESTABLISHED;
}

static void port_init(struct rte_mempool *mbuf_pool) {
	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); 
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); 
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}
	
#if ENABLE_SEND
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}
#endif
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

int main(int argc, char *argv[]) {
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}
	port_init(mbuf_pool);
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
	while (1) {
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		unsigned i = 0;
		for (i = 0; i < num_recvd; i++) {
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], 
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
					rte_pktmbuf_free(mbufs[i]);
				}
				continue;
			} 
			
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
#if ENABLE_SEND //
				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));
				rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif
				uint16_t length = ntohs(udphdr->dgram_len);
				*((char*)udphdr + length) = '\0';
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), 
					(char *)(udphdr+1));
#if ENABLE_SEND
				struct rte_mbuf *txbuf = ng_send_udp(mbuf_pool, (uint8_t *)(udphdr+1), length);
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
				rte_pktmbuf_free(txbuf);
#endif
				rte_pktmbuf_free(mbufs[i]);
			}
			if (iphdr->next_proto_id == IPPROTO_TCP){
				printf("TCP COME IN\n");
				struct rte_tcp_hdr *tcphdr =  (struct rte_tcp_hdr *)(iphdr + 1);
				tcp_stream *tcp_stream_item = query_stream(iphdr->src_addr,iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);  
				if(tcp_stream_item == NULL){
					//创建一个连接，且连接的状态为listen状态
					tcp_stream_item  = create_connect_stream(iphdr, tcphdr);
					tcp_stream_table *table = get_stream_table_instance();
					printf("新的连接,需要创建新的连接\n");
					LADD(tcp_stream_item, table->stream_item);
				}
				switch (tcp_stream_item->status)
				{
				case NG_TCP_TCP_STATUS_CLOSED:
					break;
				case NG_TCP_TCP_STATUS_LISTEN:
					handle_listen(tcp_stream_item, mbuf_pool, ehdr, iphdr, tcphdr);//解包，发包
					break;
				case NG_TCP_TCP_STATUS_SYN_RECEIVED:
					handle_syn_received(tcp_stream_item,tcphdr);//解包，发包
					break;
				default:
					break;
				}
				rte_pktmbuf_free(mbufs[i]);	
			}
			
		}

	}

}




