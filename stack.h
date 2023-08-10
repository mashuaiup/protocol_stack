#ifdef __cplusplus
extern "C" {
#endif
#ifndef STACK
#define STACK
#include <sys/socket.h>
#include <unistd.h>
#include <std.h>
#include <define.h>
int start(int argc, char *argv[]);
int udp_server_entry(__attribute__((unused))  void *arg);
int tcp_server_entry(__attribute__((unused))  void *arg);

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol);
int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen);
int nlisten(int sockfd, __attribute__((unused)) int backlog);
int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen);
ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags);
ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags);

ssize_t nreadv (int sockfd, const struct iovec *iovec, int count);
ssize_t nwritev (int sockfd, const struct iovec *iovec, int count);

ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen);
ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen);
int nclose(int fd);

int nepoll_create(int size);
int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event);
int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
#endif
#ifdef __cplusplus
}
#endif