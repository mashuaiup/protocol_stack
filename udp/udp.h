#include<protostack.h>
int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len);
struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length);