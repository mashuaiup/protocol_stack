#ifndef __TCP__
#define __TCP__
#include "protostack.h"
#include "std.h"
#include "socket.h"
#define TCP_INITIAL_WINDOW  14600
#define TCP_MAX_SQE         4294967296
#define TCP_OPTION_LENGTH	10
#define BUFFER_SIZE	        1024
typedef enum TCP_STATUS_{

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
	
}TCP_STATUS;
/* typedef struct tcp_stream_{
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

}tcp_stream; */

struct ng_tcp_stream { // tcb control block

	int fd; //

	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	
	uint8_t protocol;
	
	uint16_t sport;
	uint32_t sip;

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum

	TCP_STATUS status;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct ng_tcp_stream *prev;
	struct ng_tcp_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

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
	uint32_t length;

};

/* typedef struct tcp_stream_table_{
	uint64_t table_size;
	tcp_stream *stream_item;
}tcp_stream_table; */

struct ng_tcp_table {
	int count;
	//struct ng_tcp_stream *listener_set;	//
	struct eventpoll *ep; // single epoll
	struct ng_tcp_stream *tcb_set;
};

// tcp_stream_table *stream_table = NULL;


extern struct ng_tcp_table *tInst;

struct ng_tcp_table *tcpInstance(void);


void* get_hostinfo_fromfd(int sockfd) ;

struct ng_tcp_stream *get_accept_tcb(uint16_t dport);

// void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received);

void handle_tcp(struct rte_mbuf *mbuf, struct rte_mempool* mempool);

int ng_tcp_process(struct rte_mbuf *tcpmbuf);
int ng_tcp_out(struct rte_mempool *mbuf_pool);

struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment);
int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment);
int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen);
int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen);
int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr);
struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
int tcp_server_entry(__attribute__((unused))  void *arg);


#endif