#include "std.h"
#include <rte_malloc.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

pthread_mutex_t lhostmutex;
pthread_mutex_t tcp_tb_mutex;
pthread_mutex_t epoll_tb_mutex;

struct localhost        *lhost       =NULL;
struct ng_tcp_table     *ng_tcp_tb   =NULL;
struct ng_epoll_table   *ng_epoll_tb =NULL;
stack_arg_t sat;

unsigned char fd_table[MAX_FD_COUNT] = {0};

struct ng_tcp_table *tcpInstance(void) {
	pthread_mutex_lock(&tcp_tb_mutex);
	if(ng_tcp_tb != NULL){
		pthread_mutex_unlock(&tcp_tb_mutex);
		return ng_tcp_tb;
	}else{
		ng_tcp_tb = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(ng_tcp_tb, 0, sizeof(struct ng_tcp_table));
		pthread_mutex_unlock(&tcp_tb_mutex);
		return ng_tcp_tb;
	}
}

struct localhost *localhostInstance(void) {
	pthread_mutex_lock(&lhostmutex);
	if(lhost != NULL){
		pthread_mutex_unlock(&lhostmutex);
		return lhost;
	}else{
		lhost = rte_malloc("localhost", sizeof(struct localhost), 0);
		memset(lhost, 0, sizeof(struct localhost));
		pthread_mutex_unlock(&lhostmutex);
		return lhost;
	}
}

struct ng_epoll_table *epolltableInstance(void) {

	pthread_mutex_lock(&epoll_tb_mutex);
	if(ng_epoll_tb != NULL){
		pthread_mutex_unlock(&epoll_tb_mutex);
		return ng_epoll_tb;
	}else{
		ng_epoll_tb = rte_malloc("eptbInstance", sizeof(struct ng_epoll_table), 0);
		memset(ng_epoll_tb, 0, sizeof(struct ng_epoll_table));
		pthread_mutex_unlock(&epoll_tb_mutex);
		return ng_epoll_tb;
	}

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

struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {

	struct localhost *host;
	lhost = localhostInstance();
	for (host = lhost; host != NULL; host = host->next) {
		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}
	}
	return NULL;
}

void* get_hostinfo_fromfd(int sockfd) {
	
	struct localhost *host;
	lhost = localhostInstance();
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
	ng_tcp_tb = tcpInstance();
	for (apt = ng_tcp_tb->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}
	return NULL;
}