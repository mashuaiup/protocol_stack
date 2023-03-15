#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32

int gDpdkPortId = 0; //这边展示的是

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }//最大帧长度
};
//初始化网卡
static void ng_init_port(struct rte_mempool *mbuf_pool) {

	//查看网卡数量是不是为0
	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); //
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); //
	//配置网卡信息
	const int num_rx_queues = 1;
	const int num_tx_queues = 0;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	//配置网卡队列信息
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 128, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}
	//启动网卡
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}


int main(int argc, char *argv[]) {

	if (rte_eal_init(argc, argv) < 0) {//初始化dpdk的运行环境。
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}
/*ms
rte_pktmbuf_pool_create(const char* name,int num,int cache_size,uint16_t priv_size,uint16_t data_room_size,int socket_id):创建内存池，rte_socket_id()：返回正在运行的 lcore 所对应的物理 socket,
cache_size:设置为0 禁用缓存
priv_size通常设置为0
data_room_size Mbuf数据区大小 包括headroom大小和数据大小 默认设置为(2048+128)大包情况下要设置为(8192+128)
*/
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}
/*ms
启动网卡 
*/
	ng_init_port(mbuf_pool);

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}

		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

				uint16_t length = ntohs(udphdr->dgram_len);
				*((char*)udphdr + length) = '\0';

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), udphdr->src_port);

				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), udphdr->src_port, 
					(char *)(udphdr+1));

				rte_pktmbuf_free(mbufs[i]);
			}
			
		}

	}

}




