#include "std.h"
#include <rte_malloc.h>
#include <string.h>
struct localhost        *lhost       =NULL;
struct ng_tcp_table     *ng_tcp_tb   =NULL;
struct ng_epoll_table   *ng_epoll_tb =NULL;
unsigned char fd_table[MAX_FD_COUNT] = {0};

struct ng_tcp_table *tcpInstance(void) {

	if (ng_tcp_tb == NULL) {
		ng_tcp_tb = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(ng_tcp_tb, 0, sizeof(struct ng_tcp_table));
		
	}
	return ng_tcp_tb;
}

struct localhost *localhostInstance(void) {
	if (lhost == NULL) {
		lhost = rte_malloc("localhost", sizeof(struct localhost), 0);
		memset(lhost, 0, sizeof(struct localhost));
	}
	return lhost;
}

struct ng_epoll_table *epolltableInstance(void) {
	if (ng_epoll_tb == NULL) {
		ng_epoll_tb = rte_malloc("eptbInstance", sizeof(struct ng_epoll_table), 0);
		memset(ng_epoll_tb, 0, sizeof(struct ng_epoll_table));
	}
	return ng_epoll_tb;
}

int set_fd_frombitmap(int fd, unsigned char* fd_table) {

	if (fd >= MAX_FD_COUNT) return -1;

	fd_table[fd/8] &= ~(0x1 << (fd % 8));

	return 0;
}

int get_fd_frombitmap(unsigned char* fd_table) {

	int fd = DEFAULT_FD_NUM;
	for ( ;fd < MAX_FD_COUNT;fd ++) {
		if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}
	return -1;
}

struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto, struct localhost *listhdr) {

	struct localhost *host;

	for (host = listhdr; host != NULL; host = host->next) {
		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}
	}
	return NULL;
}

void* get_hostinfo_fromfd(int sockfd, struct localhost *lhost) {
	
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}
	}

	return NULL;	
}

void* get_stream_info_fromfd(int sockfd, struct ng_tcp_table *table){
	struct ng_tcp_stream *stream = NULL;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}
}

void* get_epoll_info_fromfd(int sockfd, struct ng_epoll_table *ng_epoll_tb){
	struct eventpoll *ep = ng_epoll_tb->ep;   //这边可以分开来写
	if (ep != NULL) {
		if (ep->fd == sockfd) {
			return ep;
		}
	}
}

struct ng_tcp_stream *get_accept_tcb(uint16_t dport) {
	struct ng_tcp_stream *apt;
	struct ng_tcp_table  *ng_tcp_tb = tcpInstance();
	for (apt = ng_tcp_tb->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}
	return NULL;
}