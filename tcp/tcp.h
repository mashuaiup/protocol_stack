#include <protostack.h>
#define TCP_INITIAL_WINDOW  14600
void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received);