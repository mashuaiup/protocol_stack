

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>


#include <stdio.h>
#include <arpa/inet.h>

#include "arp.h"

#define ENABLE_SEND		1
#define ENABLE_ARP		1
#define ENABLE_ICMP		1
#define ENABLE_ARP_REPLY	1

#define ENABLE_DEBUG		1

#define ENABLE_TIMER		1

#define ENABLE_RINGBUFFER	1
#define ENABLE_MULTHREAD	1

#define ENABLE_UDP_APP		1

#define ENABLE_TCP_APP		1



#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32
#define RING_SIZE	1024

#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 


#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 0, 115);

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

#endif

#if ENABLE_ARP_REPLY

static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif

#if ENABLE_RINGBUFFER

struct inout_ring {

	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {

	if (rInst == NULL) {

		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}

	return rInst;
}

#endif

#if ENABLE_UDP_APP

static int udp_process(struct rte_mbuf *udpmbuf);
static int udp_out(struct rte_mempool *mbuf_pool);


#endif

#if ENABLE_TCP_APP

static int ng_tcp_process(struct rte_mbuf *tcpmbuf);
static int ng_tcp_out(struct rte_mempool *mbuf_pool);


#endif


int gDpdkPortId = 0;



static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {

	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); //
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); //
	
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

/*
static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

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

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

	addr.s_addr = gDstIp;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}


static struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_pkt(pktdata, data, total_len);

	return mbuf;

}

*/

#if ENABLE_ARP


static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
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

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return 0;

}

static struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

	return mbuf;
}

#endif


#if ENABLE_ICMP


static uint16_t ng_checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	// 1 ether
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 ip
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 icmp 
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ng_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));

	return 0;
}


static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);

	return mbuf;

}


#endif

static void 
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


#if ENABLE_TIMER

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	   void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

#if 0
	struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes, 
		ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

	rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
	rte_pktmbuf_free(arpbuf);

#endif
	
	int i = 0;
	for (i = 1;i <= 254;i ++) {

		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));

		struct in_addr addr;
		addr.s_addr = dstip;
		printf("arp ---> src: %s \n", inet_ntoa(addr));

		struct rte_mbuf *arpbuf = NULL;
		uint8_t *dstmac = ng_get_dst_macaddr(dstip);
		if (dstmac == NULL) {

			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
		
		} else {

			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		}

		//rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		//rte_pktmbuf_free(arpbuf);
		rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
		
	}
	
}


#endif

#if ENABLE_MULTHREAD



static int pkt_process(void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
		
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

#if ENABLE_ARP

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {

				struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], 
					struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

				
				struct in_addr addr;
				addr.s_addr = ahdr->arp_data.arp_tip;
				printf("arp ---> src: %s ", inet_ntoa(addr));

				addr.s_addr = gLocalIp;
				printf(" local: %s \n", inet_ntoa(addr));

				if (ahdr->arp_data.arp_tip == gLocalIp) {

					if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {

						printf("arp --> request\n");

						struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, 
							ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

						//rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
						//rte_pktmbuf_free(arpbuf);

						rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);

					} else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {

						printf("arp --> reply\n");

						struct arp_table *table = arp_table_instance();

						uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);
						if (hwaddr == NULL) {

							struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
							if (entry) {
								memset(entry, 0, sizeof(struct arp_entry));

								entry->ip = ahdr->arp_data.arp_sip;
								rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
								entry->type = 0;
								
								LL_ADD(entry, table->entries);
								table->count ++;
							}

						}
#if ENABLE_DEBUG
						struct arp_entry *iter;
						for (iter = table->entries; iter != NULL; iter = iter->next) {
					
							struct in_addr addr;
							addr.s_addr = iter->ip;

							print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
								
							printf(" ip: %s \n", inet_ntoa(addr));
					
						}
#endif
						rte_pktmbuf_free(mbufs[i]);
					}
				
					continue;
				} 
			}
#endif

			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				udp_process(mbufs[i]);
				
			}

#if ENABLE_TCP_APP

			if (iphdr->next_proto_id == IPPROTO_TCP) {
				printf("ng_tcp_process\n");
				ng_tcp_process(mbufs[i]);
				
			}

#endif

#if ENABLE_ICMP

			if (iphdr->next_proto_id == IPPROTO_ICMP) {

				struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

				
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("icmp ---> src: %s ", inet_ntoa(addr));

				
				if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

					addr.s_addr = iphdr->dst_addr;
					printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
				

					struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes,
						iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

					//rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
					//rte_pktmbuf_free(txbuf);
					rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1, NULL);

					rte_pktmbuf_free(mbufs[i]);
				}
				

			}


#endif
			
		}

#if ENABLE_UDP_APP

		udp_out(mbuf_pool);

#endif


#if ENABLE_TCP_APP

		ng_tcp_out(mbuf_pool);

#endif

	}

	return 0;
}


#endif


#if ENABLE_UDP_APP



struct localhost { // 

	int fd;

	//unsigned int status; //
	uint32_t localip; // ip --> mac
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;

	uint8_t protocol;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct localhost *prev; //
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

static struct localhost *lhost = NULL;

#define DEFAULT_FD_NUM	3

static int get_fd_frombitmap(void) {

	int fd = DEFAULT_FD_NUM;
	return fd;
	
}

static struct localhost * get_hostinfo_fromfd(int sockfd) {

	struct localhost *host;

	for (host = lhost; host != NULL;host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}

	}

	
	return NULL;
	
}

static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {

	struct localhost *host;

	for (host = lhost; host != NULL;host = host->next) {

		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}

	}

	
	return NULL;
	
}

// arp
struct offload { //

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; //

	int protocol;

	unsigned char *data;
	uint16_t length;
	
}; 


static int udp_process(struct rte_mbuf *udpmbuf) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	
	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));

	struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
	if (host == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -3;
	} 

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -1;
	}

	ol->dip = iphdr->dst_addr;
	ol->sip = iphdr->src_addr;
	ol->sport = udphdr->src_port;
	ol->dport = udphdr->dst_port;

	
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udphdr->dgram_len);

	ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
	if (ol->data == NULL) {

		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);

		return -2;

	}
	rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));

	rte_ring_mp_enqueue(host->rcvbuf, ol); // recv buffer

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udpmbuf);

	return 0;
}


static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
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
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = sport;
	udp->dst_port = dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	return 0;
}


static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
		data, total_len);

	return mbuf;

}


// offload --> mbuf
static int udp_out(struct rte_mempool *mbuf_pool) {

	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {

		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		struct in_addr addr;
		addr.s_addr = ol->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
			
		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
		if (dstmac == NULL) {

			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				ol->sip, ol->dip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(host->sndbuf, ol);
			
		} else {

			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
				host->localmac, dstmac, ol->data, ol->length);

			
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);

		}
		

	}

	return 0;
}

// hook

static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {

	int fd = get_fd_frombitmap(); //

	struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
	if (host == NULL) {
		return -1;
	}
	memset(host, 0, sizeof(struct localhost));

	host->fd = fd;
	
	if (type == SOCK_DGRAM)
		host->protocol = IPPROTO_UDP;
	

	host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (host->rcvbuf == NULL) {

		rte_free(host);
		return -1;
	}

	
	host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (host->sndbuf == NULL) {

		rte_ring_free(host->rcvbuf);

		rte_free(host);
		return -1;
	}

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	LL_ADD(host, lhost);

	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
	host->localport = laddr->sin_port;
	rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
	rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	return 0;

}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	
	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
	
	int nb = -1;
	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	

	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

	if (len < ol->length) {

		rte_memcpy(buf, ol->data, len);

		ptr = rte_malloc("unsigned char *", ol->length-len, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);

		ol->length -= len;
		rte_free(ol->data);
		ol->data = ptr;
		
		rte_ring_mp_enqueue(host->rcvbuf, ol);

		return len;
		
	} else {

		rte_memcpy(buf, ol->data, ol->length);
		
		rte_free(ol->data);
		rte_free(ol);
		
		return ol->length;
	}

	

}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

	
	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;

	struct in_addr addr;
	addr.s_addr = ol->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
	

	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuf, ol);

	return len;
}

static int nclose(int fd) {

	struct localhost *host =  get_hostinfo_fromfd(fd);
	if (host == NULL) return -1;

	LL_REMOVE(host, lhost);

	if (host->rcvbuf) {
		rte_ring_free(host->rcvbuf);
	}
	if (host->sndbuf) {
		rte_ring_free(host->sndbuf);
	}

	rte_free(host);

}







#define UDP_APP_RECV_BUFFER_SIZE	128

// 
static int udp_server_entry(__attribute__((unused))  void *arg) {

	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("sockfd failed\n");
		return -1;
	} 

	struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	localaddr.sin_port = htons(8889);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.0.115"); // 0.0.0.0
	

	nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
	socklen_t addrlen = sizeof(clientaddr);
	while (1) {

		if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, 
			(struct sockaddr*)&clientaddr, &addrlen) < 0) {

			continue;

		} else {

			printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), 
				ntohs(clientaddr.sin_port), buffer);
			nsendto(connfd, buffer, strlen(buffer), 0, 
				(struct sockaddr*)&clientaddr, sizeof(clientaddr));
		}

	}

	nclose(connfd);

}




#endif


#if ENABLE_TCP_APP // ngtcp


#define TCP_OPTION_LENGTH	10

#define TCP_MAX_SEQ		4294967295

#define TCP_INITIAL_WINDOW  14600

typedef enum _NG_TCP_STATUS {

	NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN,
	NG_TCP_STATUS_SYN_RCVD,
	NG_TCP_STATUS_SYN_SENT,
	NG_TCP_STATUS_ESTABLISHED,

	NG_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,

	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK

} NG_TCP_STATUS;


struct ng_tcp_stream { // tcb control block

	int fd; //

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport;

	uint16_t proto;

	uint8_t localmac[RTE_ETHER_ADDR_LEN];

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum

	NG_TCP_STATUS status;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct ng_tcp_stream *prev;
	struct ng_tcp_stream *next;

};

struct ng_tcp_table {
	int count;
	struct ng_tcp_stream *tcb_set;
};

struct ng_tcp_fragment { 

	uint16_t sport;  
	uint16_t dport;  
	uint32_t seqnum;  
	uint32_t acknum;  
	uint8_t  hdrlen_off;  
	uint8_t  tcp_flags; 
	uint16_t windows;   
	uint16_t cksum;     
	uint16_t tcp_urp;  

	int optlen;
	uint32_t option[TCP_OPTION_LENGTH];

	unsigned char *data;
	int length;

};


struct ng_tcp_table *tInst = NULL;

static struct ng_tcp_table *tcpInstance(void) {

	if (tInst == NULL) {

		tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(tInst, 0, sizeof(struct ng_tcp_table));
		
	}
	return tInst;
}


static struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	struct ng_tcp_table *table = tcpInstance();

	struct ng_tcp_stream *iter;
	for (iter = table->tcb_set;iter != NULL; iter = iter->next) {

		if (iter->sip == sip && iter->dip == dip && 
			iter->sport == sport && iter->dport == dport) {
			return iter;
		}

	}

	return NULL;
}

static struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	// tcp --> status
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) return NULL;

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->proto = IPPROTO_TCP;

	// 
	stream->status = NG_TCP_STATUS_LISTEN;

	stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
	stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);
	
	// seq num
	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;

	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	struct ng_tcp_table *table = tcpInstance();
	LL_ADD(stream, table->tcb_set);

	return stream;
}



static int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  {

		if (stream->status == NG_TCP_STATUS_LISTEN) {

			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;
			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;

			struct in_addr addr;
			addr.s_addr = stream->sip;
			printf("tcp ---> src: %s:%d ", inet_ntoa(addr), ntohs(tcphdr->src_port));

			
			addr.s_addr = stream->dip;
			printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

			fragment->seqnum = stream->snd_nxt;
			fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
			
			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;
			
			fragment->data = NULL;
			fragment->length = 0;

			rte_ring_mp_enqueue(stream->sndbuf, fragment);
			
			stream->status = NG_TCP_STATUS_SYN_RCVD;
		}

	}

	return 0;
}


static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {

			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if (acknum == stream->snd_nxt + 1) {
				// 
			}

			stream->status = NG_TCP_STATUS_ESTABLISHED;

		}

	}
	return 0;
}


static int ng_tcp_process(struct rte_mbuf *tcpmbuf) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	

	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	
#if 1 //
	if (cksum != tcpcksum) {
		printf("cksum: %x, tcp cksum: %x\n", cksum, tcpcksum);
		return -1;
	}
#endif

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
		tcphdr->src_port, tcphdr->dst_port);
	if (stream == NULL) {
		stream = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, 
			tcphdr->src_port, tcphdr->dst_port);
		
		if (stream == NULL) return -2;
	}

	switch (stream->status) {

		case NG_TCP_STATUS_CLOSED: //client 
			break;
			
		case NG_TCP_STATUS_LISTEN: // server
			ng_tcp_handle_listen(stream, tcphdr);
			break;

		case NG_TCP_STATUS_SYN_RCVD: // server
			ng_tcp_handle_syn_rcvd(stream, tcphdr);
			break;

		case NG_TCP_STATUS_SYN_SENT: // client
			break;

		case NG_TCP_STATUS_ESTABLISHED: // server | client

			uint8_t hdrlen = tcphdr->data_off & 0xF0;
			hdrlen >= 4;
			uint8_t *payload = (uint8_t *)(tcphdr + 1) + hdrlen * 4;

			printf("payload: %s\n", payload);
			
			break;

		case NG_TCP_STATUS_FIN_WAIT_1: //  ~client
			break;
			
		case NG_TCP_STATUS_FIN_WAIT_2: // ~client
			break;
			
		case NG_TCP_STATUS_CLOSING: // ~client
			break;
			
		case NG_TCP_STATUS_TIME_WAIT: // ~client
			break;

		case NG_TCP_STATUS_CLOSE_WAIT: // ~server
			break;
			
		case NG_TCP_STATUS_LAST_ACK:  // ~server
			break;

	}

	return 0;
}


static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);

	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}


static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// mempool --> mbuf

	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

	return mbuf;

}


// struct localhost , struct tcp_stream

static int ng_tcp_out(struct rte_mempool *mbuf_pool) {

	struct ng_tcp_table *table = tcpInstance();
	
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {

		struct ng_tcp_fragment *fragment = NULL;
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip); // 
		if (dstmac == NULL) {

			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				stream->dip, stream->sip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(stream->sndbuf, fragment);

		} else {

			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);

			rte_free(fragment);
		}

	}

	return 0;
}



#endif



int main(int argc, char *argv[]) {

	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
		
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	ng_init_port(mbuf_pool);

	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

#if ENABLE_TIMER

	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif

#if ENABLE_RINGBUFFER

	struct inout_ring *ring = ringInstance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

#endif

#if ENABLE_MULTHREAD

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

#endif

#if ENABLE_UDP_APP

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

#endif


	while (1) {

		// rx
		struct rte_mbuf *rx[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (num_recvd > 0) {

			rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);
		}

		
		// tx
		struct rte_mbuf *tx[BURST_SIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {

			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

			unsigned i = 0;
			for (i = 0;i < nb_tx;i ++) {
				rte_pktmbuf_free(tx[i]);
			}
			
		}
		


#if ENABLE_TIMER

		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}

#endif


	}

}




