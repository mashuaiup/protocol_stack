#include <protostack.h>
#define TCP_INITIAL_WINDOW  14600
#define TCP_MAX_SQE 4294967296

#define LADD(item, list) do { \
    item->next = list; \
    item->pre = NULL; \
    if(list != NULL) list->pre = item; \
    list = item; \
}while(0);

typedef enum TCP_STATUS_{
	NG_TCP_TCP_STATUS_CLOSED=0,
	NG_TCP_TCP_STATUS_LISTEN=1,
	NG_TCP_TCP_STATUS_SYN_RECEIVED,
	NG_TCP_TCP_STATUS_SYN_SEND,
	NG_TCP_TCP_STATUS_ESTABLISHED,
	NG_TCP_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_TCP_STATUS_CLOSING,
	NG_TCP_TCP_STATUS_TIME_WAIT,
	NG_TCP_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_TCP_STATUS_LASK_ACK
}TCP_STATUS;
typedef struct tcp_stream_{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
	uint8_t status;
	uint32_t send_sqe;
	uint32_t recv_sqe;
	struct tcp_stream_ *pre;
	struct tcp_stream_ *next;

}tcp_stream;

typedef struct tcp_stream_table_{
	uint64_t table_size;
	tcp_stream *stream_item;
}tcp_stream_table;

static tcp_stream_table *stream_table = NULL;
void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received);
void handle_tcp(struct rte_mbuf *mbuf, struct rte_mempool* mempool);

