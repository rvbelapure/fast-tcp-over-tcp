#ifndef __GTTCP_H
#define __GTTCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#define SYN_FLAG 1
#define ACK_FLAG 2
#define FIN_FLAG 4
#define COOKIE_REQ_FLAG 8
#define FAST_OPEN_FLAG 16

#define MAX_PEERS 100

extern uint32_t CCgen;

typedef enum
{
	CC,
	CC_NEW,
	CC_ECHO,
	NO_CC
} cc_flag_t;

typedef struct  _cc_cache
{
	uint32_t *CC;
	uint32_t *CCsent;
}cc_cache_t;

typedef struct _cc_options
{
	cc_flag_t cc;
	uint32_t seg_cc;
}cc_options_t;

typedef struct _tcp_packet 
{
	char *ubuf;
	size_t ulen;
	int uflags;
	uint32_t gt_flags;
	unsigned long cookie; //unused for T/TCP
	cc_options_t cc_options; //Added for T/TCP

}tcp_packet_t;

typedef struct _sock_descriptor
{
	int sockfd;
	char *data;
	ssize_t offset;
	ssize_t length;

	uint32_t CCsend; //Added for T/TCP
	uint32_t CCrecv;

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

typedef struct handshake_params{
	sock_descriptor_t *hs_sockfd;
	sock_descriptor_t *app_sockfd;
	void *app_func;
	void *app_func_params;
}handshake_params_t;

sock_descriptor_t * gt_socket(int domain, int type, int protocol);
int gt_listen(sock_descriptor_t * sockfd, int backlog);
int gt_bind(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
//int gt_connect(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, 
	unsigned long cookie, char * udata, ssize_t ulen);
//sock_descriptor_t *gt_accept(sock_descriptor_t * sockfd, struct sockaddr *addr, socklen_t *addrlen);
sock_descriptor_t *gt_accept(sock_descriptor_t * sockfd, struct sockaddr *addr, socklen_t *addrlen, 
	void *app_func, void *app_func_param);
ssize_t gt_send(sock_descriptor_t * sockfd, const void *buf, size_t len, int flags);
ssize_t gt_recv(sock_descriptor_t * sockfd, void *buf, size_t len, int flags);
int gt_close(sock_descriptor_t * sockfd);

#endif
