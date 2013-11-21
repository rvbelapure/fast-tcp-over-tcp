#ifndef __GTTCP_H
#define __GTTCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>

#define SYN_FLAG 1
#define ACK_FLAG 2
#define FIN_FLAG 4
#define COOKIE_REQ_FLAG 8
#define FAST_OPEN_FLAG 16

typedef struct _tcp_packet 
{
	char *ubuf;
	size_t ulen;
	int uflags;
	uint32_t gt_flags;
	unsigned long cookie;
}tcp_packet_t;

typedef struct _sock_descriptor
{
	int sockfd;
	char *data;
	ssize_t offset;
	ssize_t length;
}sock_descriptor_t;

typedef struct _thread_args
{
	pid_t app_tid;
	sock_descriptor_t appd;
	sock_descriptor_t hsd;
	unsigned long cookie;
	char *udata;
	ssize_t ulen;
}thread_args_t;

sock_descriptor_t * gt_socket(int domain, int type, int protocol);
int gt_listen(sock_descriptor_t * sockfd, int backlog);
int gt_bind(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned long cookie, char * udata, ssize_t ulen);
sock_descriptor_t *gt_accept(sock_descriptor_t * sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t gt_send(sock_descriptor_t * sockfd, const void *buf, size_t len, int flags);
ssize_t gt_recv(sock_descriptor_t * sockfd, void *buf, size_t len, int flags);
int gt_close(sock_descriptor_t * sockfd);

void * gt_connect_handshake_thread(void * arguments);

#endif
