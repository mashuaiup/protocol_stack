#include "socket.h"
#include "stack.h"
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <string.h>
#include <rte_memcpy.h>

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {

	int fd = get_fd_frombitmap(fd_table); //

	if (type == SOCK_DGRAM) {
		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL) {
			return -1;
		}
		memset(host, 0, sizeof(struct localhost));

		host->fd = fd;
		
		host->protocol = IPPROTO_UDP;

		host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuf == NULL) {
			rte_free(host);
			return -1;
		}

		host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuf == NULL) {
			rte_ring_free(host->rcvbuf);
			rte_free(host);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));
		lhost = localhostInstance();
		LL_ADD(host, lhost); 

	} else if (type == SOCK_STREAM) {
		struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
		if (stream == NULL) {
			return -1;
		}
		memset(stream, 0, sizeof(struct ng_tcp_stream));
		stream->fd = fd;
		stream->protocol = IPPROTO_TCP;
		stream->next = stream->prev = NULL;
		stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->rcvbuf == NULL) {
			rte_free(stream);
			return -1;
		}

		stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->sndbuf == NULL) {
			rte_ring_free(stream->rcvbuf);
			rte_free(stream);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		ng_tcp_tb = tcpInstance();
		LL_ADD(stream, ng_tcp_tb->tcb_set); //hash  
	}
	return fd;
}

int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused)) socklen_t addrlen) {
	
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) {
		ng_tcp_tb = tcpInstance();
		struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
		if(stream){
			const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
			stream->dport = laddr->sin_port;
			rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
			stream->status = NG_TCP_STATUS_CLOSED;
		}else{
			return -1;
		}
	}else{
		struct localhost *host = (struct localhost *)hostinfo;
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
	}
	return 0;
}

int nlisten(int sockfd, __attribute__((unused)) int backlog) { //
	ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
	if(stream == NULL) return -1;
		
	if (stream->protocol == IPPROTO_TCP) {
		stream->status = NG_TCP_STATUS_LISTEN;
	}
	return 0;
}

int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {
	ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
	if(stream == NULL) return -1;

	if (stream->protocol == IPPROTO_TCP) {
		struct ng_tcp_stream *apt = NULL;
		pthread_mutex_lock(&stream->mutex);
		while((apt = get_accept_tcb(stream->dport)) == NULL) {  //block to wait msg sended by client
			pthread_cond_wait(&stream->cond, &stream->mutex);
		} 
		pthread_mutex_unlock(&stream->mutex);
		apt->fd = get_fd_frombitmap(fd_table);
		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = apt->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));
		return apt->fd;
	}
	return -1;
}

ssize_t nsend(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags) {
	ssize_t length = 0;

	ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
	if(stream == NULL) return -1;

	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) {
			return -2;
		}
		memset(fragment, 0, sizeof(struct ng_tcp_fragment));

		fragment->dport = stream->sport;
		fragment->sport = stream->dport;
		fragment->acknum = stream->rcv_nxt;
		fragment->seqnum = stream->snd_nxt;
		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->hdrlen_off = 0x50;
		fragment->data = rte_malloc("unsigned char *", len+1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len+1);
		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;
		// int nb_snd = 0;
		rte_ring_mp_enqueue(stream->sndbuf, fragment);
	}
	return length;
}

ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
	ssize_t length = 0;

	ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
	if(stream == NULL) return -1;

	if (stream->protocol == IPPROTO_TCP) {
		struct ng_tcp_fragment *fragment = NULL;
		int nb_rcv = 0;
		pthread_mutex_lock(&stream->mutex);
		while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		if (fragment->length > len) {
			rte_memcpy(buf, fragment->data, len);
			uint32_t i = 0;
			for(i = 0;i < fragment->length-len;i ++) {
				fragment->data[i] = fragment->data[len+i];
			}
			fragment->length = fragment->length-len;
			length = fragment->length;
			rte_ring_mp_enqueue(stream->rcvbuf, fragment);
		} else if (fragment->length == 0) {
			rte_free(fragment);
			return 0;
		} else {
			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;
			rte_free(fragment->data);
			fragment->data = NULL;
			rte_free(fragment);
		}
	}
	return length;
}
ssize_t nreadv (int sockfd, const struct iovec *iovec, int count) {
	/* only support count_max <= 2*/
	if(count > 2) return -1;
	struct iovec *iov0 = (struct iovec *)iovec;
	int len0 = iov0->iov_len;
	struct iovec *iov1 = iov0 + 1;
	int len1 = iov1->iov_len;
	
 	ssize_t length = -1;
	ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
	if(stream == NULL) return -1;

	struct ng_tcp_fragment *fragment = NULL;
	int nb_rcv = 0;
	//get data from fd->recvbuf  block!
	pthread_mutex_lock(&stream->mutex);
	while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
		pthread_cond_wait(&stream->cond, &stream->mutex);
	}
	pthread_mutex_unlock(&stream->mutex);

	
	/* 1: 0 < length < len0;
	   2: len0 < length < len0+len1
	   3: len0 + len1 < length*/

	if(fragment->length <= 0){
		rte_free(fragment);
		return -1;
	}else if(fragment->length <= len0){
		char show_buff[65535];
		rte_memcpy(show_buff, fragment->data, fragment->length);
		printf("show_buff : %s\n", show_buff);
		rte_memcpy(iov0->iov_base, fragment->data, fragment->length);
	}else if(fragment->length > len0 && fragment->length < len0 + len1){
		char show_buff[65535];
		rte_memcpy(iov0->iov_base, fragment->data, len0);
		rte_memcpy(iov1->iov_base, fragment->data + len0, fragment->length - len0);
		printf("show_buff : %s\n", show_buff);
	}
	printf("readv message from client: %s \n", fragment->data);
	
	printf("iov0收到的数据为:%s\n", iov0->iov_base);
	printf("iov1收到的数据为:%s\n", iov1->iov_base);
	length = fragment->length;
	rte_free(fragment->data);
	fragment->data = NULL;
	rte_free(fragment);
	return length;
}

ssize_t nwritev (int sockfd, const struct iovec *iovec, int count){
	printf("nwritev count is %d\n", count);
	if(count > 2) return -1;

	struct iovec *iov0 = (struct iovec *)iovec;
	size_t len0 = iov0->iov_len;

	struct iovec *iov1 = NULL;
	size_t len1 = 0;
	if(count == 2){
		iov1 = iov0 + 1;
		// iov1 = (struct iovec *)(iov0->iov_base + len0);
		len1 = iov1->iov_len;
		printf("++++++++++++++iov0准备发送的数据:%s\n", iov0->iov_base);
		printf("++++++++++++++iov1准备发送的数据:%s\n", iov1->iov_base);
	}
	ssize_t length = -1;

	ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream = get_stream_info_fromfd(sockfd, ng_tcp_tb);
	if(stream == NULL) return -1;

	struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (fragment == NULL) {
		return -2;
	}
	memset(fragment, 0, sizeof(struct ng_tcp_fragment));

	fragment->dport = stream->sport;
	fragment->sport = stream->dport;
	fragment->acknum = stream->rcv_nxt;
	fragment->seqnum = stream->snd_nxt;
	fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
	fragment->windows = TCP_INITIAL_WINDOW;
	fragment->hdrlen_off = 0x50;

	if(count == 1){
		length = len0;
		fragment->data = rte_malloc("unsigned char *", length + 1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, length + 1);
		rte_memcpy(fragment->data, iov0->iov_base, length);
	}else if(count == 2){
		length = len0 + len1;
		fragment->data = rte_malloc("unsigned char *", length + 1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, length + 1);
		rte_memcpy(fragment->data, iov0->iov_base, len0);
		rte_memcpy(fragment->data + len0, iov1->iov_base, len1);
	}

	printf("writev message from server: %s \n", fragment->data);

	fragment->length = length + 1;
	// int nb_snd = 0;
	rte_ring_mp_enqueue(stream->sndbuf, fragment);

	return length;

}

ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {
	
	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	
	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
	
	int nb = -1;
	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	

	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

	if (len < ol->length) {

		rte_memcpy(buf, ol->data, len);

		ptr = rte_malloc("unsigned char *", ol->length-len, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);

		ol->length -= len;
		rte_free(ol->data);
		ol->data = ptr;
		
		rte_ring_mp_enqueue(host->rcvbuf, ol);

		return len;
		
	} else {

		int length = ol->length;
		rte_memcpy(buf, ol->data, ol->length);
		
		rte_free(ol->data);
		rte_free(ol);
		
		return length;
	}
}

ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

	
	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;

	struct in_addr addr;
	addr.s_addr = ol->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
	addr.s_addr = ol->sip;
	printf("nsendto ---> drc: %s:%d \n", inet_ntoa(addr), ntohs(ol->sport));
	
	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuf, ol);

	return len;
}

int nclose(int fd) {
	struct localhost *host = get_hostinfo_fromfd(fd);
	if (host == NULL) {
		ng_tcp_tb = tcpInstance();
		struct ng_tcp_stream *stream = get_stream_info_fromfd(fd, ng_tcp_tb);
		if(stream){
			if (stream->status != NG_TCP_STATUS_LISTEN) {
				struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
				if (fragment == NULL) return -1;
				// printf("nclose --> enter last ack\n");
				fragment->data = NULL;
				fragment->length = 0;
				fragment->sport = stream->dport;
				fragment->dport = stream->sport;

				fragment->seqnum = stream->snd_nxt;
				fragment->acknum = stream->rcv_nxt;

				fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
				fragment->windows = TCP_INITIAL_WINDOW;
				fragment->hdrlen_off = 0x50;

				rte_ring_mp_enqueue(stream->sndbuf, fragment);
				stream->status = NG_TCP_STATUS_LAST_ACK;
				set_fd_frombitmap(fd, fd_table);

			} else { // nsocket
				ng_tcp_tb = tcpInstance();
				LL_REMOVE(stream, ng_tcp_tb->tcb_set);	
				rte_free(stream);
			}
		}else{
			return -1;
		}

	}else{
		LL_REMOVE(host, lhost);
		if (host->rcvbuf) {
			rte_ring_free(host->rcvbuf);
		}
		if (host->sndbuf) {
			rte_ring_free(host->sndbuf);
		}
		rte_free(host);
		set_fd_frombitmap(fd, fd_table);
	}

	return 0;
}