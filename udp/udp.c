#include "udp.h"
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_malloc.h>
int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport,
	unsigned char *data, uint16_t total_len) {

	// encode 
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	rte_memcpy(eth->s_addr.addr_bytes, gDefaultArpMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDefaultArpMac, RTE_ETHER_ADDR_LEN);
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

struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *data, uint16_t length) {

	// mempool --> mbuf
	const unsigned total_len = length + 42;
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, data, total_len);
	return mbuf;

}

int udp_server_entry(__attribute__((unused))  void *arg) {

	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("sockfd failed\n");
		return -1;
	} 

	struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	localaddr.sin_port = htons(8889);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.123.199"); // 0.0.0.0
	
	nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
	socklen_t addrlen = sizeof(clientaddr);
	while(1) {

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

int udp_process(struct rte_mbuf *udpmbuf, struct localhost *udp_tb_lhead) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));
	addr.s_addr = iphdr->dst_addr;
	printf("udp_process ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->dst_port));

	struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
	if (host == NULL) {
		printf("udp的目的ip和端口与服务器不匹配\n");
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

void udp_out(struct rte_mempool *mbuf_pool, struct inout_ring* ioa_ring, struct localhost *lhost) {
	
	struct localhost *host;
	lhost = localhostInstance();
	for (host = lhost; host != NULL; host = host->next) {
		struct offload *ol;
		if(host->sndbuf == NULL)
			continue;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;
		//fill upd packet without mac addr
		struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, ol->data, ol->length);
		int num = rte_ring_sp_enqueue_burst(ioa_ring->arp_ring, (void **)&udpbuf, 1, NULL);
		if(num <= 0){
			printf("数据存入ioa_ring->arp_ring失败\n");
		}
		if (ol->data != NULL){
			rte_free(ol->data);
		}
		rte_free(ol);
	}
}