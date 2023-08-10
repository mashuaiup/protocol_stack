// #include "protostack.h"
#include "socket.h"
#include <rte_mbuf.h>

// int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
// 	uint16_t sport, uint16_t dport,unsigned char *data, uint16_t total_len);
struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport,uint8_t *data, uint16_t length);
int udp_process(struct rte_mbuf *udpmbuf, struct localhost *udp_tb_lhead);
void udp_out(struct rte_mempool *mbuf_pool, struct inout_ring* ioa_ring, struct localhost *lhost);

