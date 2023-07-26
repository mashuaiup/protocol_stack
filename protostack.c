#include <rte_eal.h>

#include <time.h>
#include <stdio.h>
#include "protostack.h"
#include <rte_ether.h>

uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 123, 199);

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
	
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

static int pkt_process(void *arg) {
	stack_arg_t *stack_st = (stack_arg_t*)arg;
	struct rte_mempool *mbuf_pool = stack_st->mbuf_pool;
	struct inout_ring *ring = stack_st->io_ring;
	arp_arg_t *arp_st = (arp_arg_t*)stack_st->arp_arg;
	// tcp_arg_t *tcp_st = (tcp_arg_t*)stack_st->tcp_arg;
	while (1) {
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
		unsigned i = 0;
		for (i = 0;i < num_recvd; i++) {
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				arp_process(mbufs[i], mbuf_pool, arp_st, ring);
			}
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
				// ng_arp_entry_insert(iphdr->src_addr, ehdr->s_addr.addr_bytes, arp_st);
				if (iphdr->next_proto_id == IPPROTO_UDP) {
					lhost = localhostInstance();
					udp_process(mbufs[i], lhost);
				} else if (iphdr->next_proto_id == IPPROTO_TCP) {
					ng_tcp_tb  = tcpInstance();
					ng_epoll_tb  = epolltableInstance();
					ng_tcp_process(mbufs[i], ng_tcp_tb, ng_epoll_tb);
				}
			} 
		}
		lhost = localhostInstance();
		udp_out(mbuf_pool, ring, lhost);
		ng_tcp_tb  = tcpInstance();
		ng_tcp_out(mbuf_pool, ring, ng_tcp_tb);
		arp_out(mbuf_pool, ring, arp_st);
	}
	return 0;
}

int stack_info_init(stack_arg_t * stack_arg){
	
	//init arp info
	stack_arg->arp_arg = rte_malloc("arp_arg", sizeof(arp_arg_t), 0);
	arp_arg_t* arp_arg = (arp_arg_t *)stack_arg->arp_arg;
	arp_arg->arp_tb = (struct arp_table *)rte_malloc("arp_table", sizeof(struct arp_table), 0);
	arp_arg->arp_tb->entries = (struct arp_entry*)rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
	if(stack_arg->arp_arg == NULL || arp_arg->arp_tb == NULL || arp_arg->arp_tb->entries == NULL){
		return 0;
	}
	
	arp_arg->gLocalIp = gLocalIp;
	// memset(arp_arg->gDefaultArpMac, 0xFF, RTE_ETHER_ADDR_LEN);
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)arp_arg->gSrcMac);

	//init frame
	stack_arg->io_ring = rte_malloc("in/out/arp ring", sizeof(struct inout_ring), 0);
	if (stack_arg->io_ring->in == NULL) {
		stack_arg->io_ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (stack_arg->io_ring->out == NULL) {
		stack_arg->io_ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (stack_arg->io_ring->arp_ring == NULL) {
		stack_arg->io_ring->arp_ring = rte_ring_create("arp ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (stack_arg->io_ring == NULL || stack_arg->io_ring->in == NULL || stack_arg->io_ring->out == NULL || stack_arg->io_ring->arp_ring == NULL) {
		rte_free(stack_arg->arp_arg);
		return 0;
	}

	//init memepool
	stack_arg->mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(stack_arg->mbuf_pool == NULL){
		rte_free(stack_arg->arp_arg);
		rte_free(stack_arg->io_ring);
		return 0;
	}

	return 1;
}

int main(int argc, char *argv[]) {
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}
	stack_arg_t sat;
	int res = stack_info_init(&sat);
	if(res == 0){
		rte_exit(EXIT_FAILURE, "Init stack info failed\n");
	}

	pthread_mutex_init(&lhostmutex, NULL);
	pthread_mutex_init(&tcp_tb_mutex, NULL);
	pthread_mutex_init(&epoll_tb_mutex, NULL);

	port_init((&sat)->mbuf_pool);
	rte_timer_subsystem_init();
	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);
	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, &sat);

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, &sat, lcore_id);
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(udp_server_entry, &sat, lcore_id);
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(tcp_server_entry, &sat, lcore_id);

	while(1) {
		// rx
		struct rte_mbuf *rx[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (num_recvd > 0) {
			rte_ring_sp_enqueue_burst((&sat)->io_ring->in, (void**)rx, num_recvd, NULL);
		}
		// tx
		struct rte_mbuf *tx[BURST_SIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst((&sat)->io_ring->out, (void**)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {
			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
			unsigned i = 0;
			for (i = 0;i < nb_tx;i ++) {
				rte_pktmbuf_free(tx[i]);
			}
		}
		
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
}
