#include <rte_eal.h>

#include <time.h>
#include <stdio.h>
#include "protostack.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"

#define ENABLE_SEND		1
#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32
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
			//handle arp
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				handle_arp(mbufs[i], mbuf_pool);
				continue;
			}
			//handle ip
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
		    //handle udp
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				handle_udp(mbufs[i], mbuf_pool);
				continue;
			}
			//handle tcp
			if (iphdr->next_proto_id == IPPROTO_TCP){
				handle_tcp(mbufs[i], mbuf_pool);
			}
		}

	}

}




