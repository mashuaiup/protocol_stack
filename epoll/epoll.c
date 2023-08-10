#include "epoll.h"
#include "stack.h"
#include <rte_malloc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int sockfd_cmp(struct epitem *ep1, struct epitem *ep2) {
	if (ep1->sockfd < ep2->sockfd) return -1;
	else if (ep1->sockfd == ep2->sockfd) return 0;
	return 1;
}


RB_GENERATE_STATIC(_epoll_rb_socket, epitem, rbn, sockfd_cmp);

/* 功能：更新epoll实例中socket对应的红黑树节点中的时间类型，并添加到就绪列表中
 */
int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event) {

	struct epitem tmp;
	tmp.sockfd = sockid;
	struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp); //

	if (!epi) {
		printf("rbtree not exist\n");
		return -1;
	}

	if (epi->rdy) {                               //如果是就绪的话就直接更新事件为 epoll in
		epi->event.events |= event;
		return 1;
	} 

	printf("epoll_event_callback --> %d\n", epi->sockfd);
	
	pthread_spin_lock(&ep->lock);
	epi->rdy = 1;
	LIST_INSERT_HEAD(&ep->rdlist, epi, rdlink);   //将epi插入到就绪列表中
	ep->rdnum ++;
	pthread_spin_unlock(&ep->lock);

	pthread_mutex_lock(&ep->cdmtx);
	pthread_cond_signal(&ep->cond);              //条件变量唤醒
	pthread_mutex_unlock(&ep->cdmtx);
}

int nepoll_create(int size) {
	if (size <= 0) return -1;
	//epfd --> struct eventpoll
	int epfd = get_fd_frombitmap(fd_table); //tcp, udp
	struct eventpoll *ep = (struct eventpoll*)rte_malloc("eventpoll", sizeof(struct eventpoll), 0);
	if (!ep) {
		set_fd_frombitmap(epfd, fd_table);
		return -1;
	}
	ng_epoll_tb = epolltableInstance();
	ng_epoll_tb->ep = ep;
	
	ep->fd = epfd;
	ep->rbcnt = 0;
	RB_INIT(&ep->rbr);
	LIST_INIT(&ep->rdlist);
	if (pthread_mutex_init(&ep->mtx, NULL)) {
		free(ep);
		set_fd_frombitmap(epfd, fd_table);
		
		return -2;
	}
	if (pthread_mutex_init(&ep->cdmtx, NULL)) {
		pthread_mutex_destroy(&ep->mtx);
		free(ep);
		set_fd_frombitmap(epfd, fd_table);
		return -2;
	}
	if (pthread_cond_init(&ep->cond, NULL)) {
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		free(ep);
		set_fd_frombitmap(epfd, fd_table);
		return -2;
	}
	if (pthread_spin_init(&ep->lock, PTHREAD_PROCESS_SHARED)) {
		pthread_cond_destroy(&ep->cond);
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		free(ep);

		set_fd_frombitmap(epfd, fd_table);
		return -2;
	}
	return epfd;
}

int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event) {
	struct eventpoll *ep = (struct eventpoll*)get_epoll_info_fromfd(epfd, epolltableInstance());
	if (!ep || (!event && op != EPOLL_CTL_DEL)) {
		//errno = -EINVAL;
		return -1;
	}

	if (op == EPOLL_CTL_ADD) {

		pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) {
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		epi = (struct epitem*)rte_malloc("epitem", sizeof(struct epitem), 0);
		if (!epi) {
			pthread_mutex_unlock(&ep->mtx);
			// rte_errno = -ENOMEM;
			return -1;
		}
		
		epi->sockfd = sockid;
		memcpy(&epi->event, event, sizeof(struct epoll_event));

		epi = RB_INSERT(_epoll_rb_socket, &ep->rbr, epi);

		ep->rbcnt ++;
		
		pthread_mutex_unlock(&ep->mtx);

	} else if (op == EPOLL_CTL_DEL) {

		pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		
		if (!epi) {
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}
		epi = RB_REMOVE(_epoll_rb_socket, &ep->rbr, epi);
		if (!epi) {
			
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}
		ep->rbcnt --;
		// free(ep);
		pthread_mutex_unlock(&ep->mtx);

	} else if (op == EPOLL_CTL_MOD) {

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) {
			epi->event.events = event->events;
			epi->event.events |= EPOLLERR | EPOLLHUP;
		} else {
			// rte_errno = -ENOENT;
			return -1;
		}
	} 
	return 0;
}

int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {

	struct eventpoll *ep = (struct eventpoll*)get_epoll_info_fromfd(epfd, epolltableInstance());
	if (!ep || !events || maxevents <= 0) {
		rte_errno = -EINVAL;
		return -1;
	}

	if (pthread_mutex_lock(&ep->cdmtx)) {
		if (rte_errno == EDEADLK) {
			printf("epoll lock blocked\n");
		}
	}

	while (ep->rdnum == 0 && timeout != 0) {
		ep->waiting = 1;
		if (timeout > 0) {
			struct timespec deadline;
			clock_gettime(CLOCK_REALTIME, &deadline);
			if (timeout >= 1000) {
				int sec;
				sec = timeout / 1000;
				deadline.tv_sec += sec;
				timeout -= sec * 1000;
			}

			deadline.tv_nsec += timeout * 1000000;

			if (deadline.tv_nsec >= 1000000000) {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000;
			}

			int ret = pthread_cond_timedwait(&ep->cond, &ep->cdmtx, &deadline);
			if (ret && ret != ETIMEDOUT) {
				printf("pthread_cond_timewait\n");
				
				pthread_mutex_unlock(&ep->cdmtx);
				
				return -1;
			}
			timeout = 0;
		} else if (timeout < 0) {

			int ret = pthread_cond_wait(&ep->cond, &ep->cdmtx);
			if (ret) {
				printf("pthread_cond_wait\n");
				pthread_mutex_unlock(&ep->cdmtx);

				return -1;
			}
		}
		ep->waiting = 0; 

	}

	pthread_mutex_unlock(&ep->cdmtx);

	pthread_spin_lock(&ep->lock);

	int cnt = 0;
	int num = (ep->rdnum > maxevents ? maxevents : ep->rdnum);
	int i = 0;
	
	while (num != 0 && !LIST_EMPTY(&ep->rdlist)) { //EPOLLET

		struct epitem *epi = LIST_FIRST(&ep->rdlist);
		LIST_REMOVE(epi, rdlink);
		epi->rdy = 0;

		memcpy(&events[i++], &epi->event, sizeof(struct epoll_event));
		
		num --;
		cnt ++;
		ep->rdnum --;
	}
	
	pthread_spin_unlock(&ep->lock);

	return cnt;
}
