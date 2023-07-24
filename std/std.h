#ifndef __STD__
#define __STD__
#include <stdint.h>
#include "nty_tree.h"
#include "define.h"
#include <pthread.h>
#include <sys/queue.h>


//list
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)
struct offload { //

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; //

	int protocol;

	unsigned char *data;
	uint16_t length;
	
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
//ring
struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
	struct rte_ring *arp_ring;
};

//udp&host
struct localhost { // 
	int fd;
	//unsigned int status; //
	uint32_t localip; 
	uint16_t localport;

	uint8_t protocol;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct localhost *prev; //
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};
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

//tcp
struct ng_tcp_stream { // tcb control block

	int fd; //

	uint32_t dip;
	// uint8_t localmac[RTE_ETHER_ADDR_LEN];
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

struct ng_tcp_table {
	int count;
	struct ng_tcp_stream *tcb_set;
};

//epoll
typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
};

struct epitem {
	RB_ENTRY(epitem) rbn;
	LIST_ENTRY(epitem) rdlink;
	int rdy; //exist in list 
	
	int sockfd;
	struct epoll_event event; 
};

RB_HEAD(_epoll_rb_socket, epitem);
typedef struct _epoll_rb_socket ep_rb_tree;

struct eventpoll {                //epoll实例
	int fd;                       //epoll实例的文件描述符，用于管理epoll实例，而不是服务器端的文件描述符

	ep_rb_tree rbr;
	int rbcnt;
	
	LIST_HEAD( ,epitem) rdlist;   //就绪列表
	int rdnum;

	int waiting;

	pthread_mutex_t mtx; //rbtree update
	pthread_spinlock_t lock; //rdlist update
	
	pthread_cond_t cond; //block for event
	
	pthread_mutex_t cdmtx; //mutex for cond
};

struct ng_epoll_table {
	int count;
	struct eventpoll *ep; // single epoll
};

//stack all
typedef struct stack_arg{
	struct rte_mempool *mbuf_pool;
	struct inout_ring *io_ring;
	void* arp_arg;
	// void* tcp_arg;
	void* epoll_arg;
}stack_arg_t;

extern struct localhost        *lhost;
extern struct ng_tcp_table     *ng_tcp_tb;
extern struct ng_epoll_table   *ng_epoll_tb;
extern unsigned char fd_table[MAX_FD_COUNT];

struct ng_tcp_table *tcpInstance(void);
struct localhost *localhostInstance(void);
struct ng_epoll_table *epolltableInstance(void);

struct ng_tcp_stream* get_accept_tcb(uint16_t dport);

int  set_fd_frombitmap(int fd, unsigned char* fd_table);
int  get_fd_frombitmap(unsigned char* fd_table);
struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto);

void* get_hostinfo_fromfd(int sockfd);
void* get_stream_info_fromfd(int sockfd, struct ng_tcp_table *table);
void* get_epoll_info_fromfd(int sockfd, struct ng_epoll_table *ng_epoll_tb);


#endif
