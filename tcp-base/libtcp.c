#include <sys/types.h>
#include <sys/socket.h>

#include "tcp.h"

int gt_listen(int sockfd, int backlog) {

	listen(sockfd, backlog);
}
int gt_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	bind(sockfd, addr, addrlen);
}
int gt_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {}
int gt_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	int new_sockid = accept(sockfd, addr, addrlen);
}
ssize_t gt_send(int sockfd, const void *buf, size_t len, int flags) {}
size_t gt_recv(int sockfd, void *buf, size_t len, int flags) {}
int gt_close(int sockfd) {}
