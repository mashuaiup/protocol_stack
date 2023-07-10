#include "protostack.h"
#include "socket.h"
#define UDP_APP_RECV_BUFFER_SIZE	128

int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len);
struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length);
void handle_udp(struct rte_mbuf * mbuf, struct rte_mempool* mbuf_pool);
int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len);
struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	uint8_t *data, uint16_t length);

int udp_process(struct rte_mbuf *udpmbuf);
int udp_out(struct rte_mempool *mbuf_pool);
int udp_server_entry(__attribute__((unused))  void *arg);
