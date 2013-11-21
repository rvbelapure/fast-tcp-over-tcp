#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "tcp.h"
#include "tcputils.h"

uint32_t CCgen = 1;
cc_cache_t cache;
#ifdef __SERVER
uint32_t num_clients = 0;
#endif

void gt_init(){

#ifdef __SERVER	
	cache.CC = (uint32_t *)calloc(MAX_PEERS, sizeof(uint32_t));
	cache.CCsent = (uint32_t *)calloc(MAX_PEERS, sizeof(uint32_t));
#endif

#ifdef __CLIENT	
	cache.CC = (uint32_t *)calloc(1, sizeof(uint32_t));
	cache.CCsent = (uint32_t *)calloc(1, sizeof(uint32_t));
#endif

}

sock_descriptor_t * gt_socket(int domain, int type, int protocol)
{
	sock_descriptor_t * sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	sockfd->sockfd = socket(domain, type, protocol);
	sockfd->data = NULL;
	sockfd->offset = 0;
	sockfd->length = 0;

//Added for T/TCP
	sockfd->CCrecv = 0;
	sockfd->CCsend = 0;

	return sockfd;
}

int gt_listen(sock_descriptor_t *sockfd, int backlog) {
	return listen(sockfd->sockfd, backlog);
}
int gt_bind(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	return bind(sockfd->sockfd, addr, addrlen);
}
ssize_t gt_connect_and_send(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, 
			const void *buf, size_t len, int flags) {
	int sockfd_conn = sockfd->sockfd;
	int err = connect(sockfd_conn, addr, addrlen);
	if(err)
		return err;

	sockfd->CCrecv = 0;
	sockfd->CCsend = get_CCgen();

	tcp_packet_t *syn_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_pkt->ubuf = NULL;
	syn_pkt->ulen = 0;
	syn_pkt->uflags = 0;
	syn_pkt->gt_flags |= SYN_FLAG;

	//Client will talk to only one server
	//So client side CC cache is only a single element wide
	if((cache.CCsent[0] == 0)/*Haven't talked to this server before*/ 
		|| (sockfd->CCsend < cache.CCsent[0]) /*CCgen wrapped around due to too many transactions*/){
		cc_options_t cc_opt;
		cc_opt.cc = CC.NEW;
		cc_opt.seg_cc = sockfd->CCsend;
		cache.CCsent[0] = 0;
	} else {
		cc_options_t cc_opt;
		cc_opt.cc = CC;
		cc_opt.seg_cc = sockfd->CCsend;
		cache.CCsent[0] = sockfd->CCsend;
	}
//Can send data with SYN here
	syn_pkt->ubuf = (char *) malloc(len * sizeof(char));
	memcpy(syn_pkt->ubuf, buf, len);
	syn_pkt->ulen = len;
	syn_pkt->uflags = flags;
	//syn_pkt->gt_flags = 0;
	return gt_send_size(sockfd->sockfd,syn_pkt);

//SYN is sent at this point

	tcp_packet_t *syn_ack_pkt = NULL;
	gt_recv_size(sockfd_conn, &syn_ack_pkt);
	assert((syn_ack_pkt->gt_flags & SYN_FLAG) && (syn_ack_pkt->gt_flags & ACK_FLAG));
//SYN, ACK is received at this point

	tcp_packet_t *ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	ack_pkt->ubuf = NULL;
	ack_pkt->ulen = 0;
	ack_pkt->uflags = 0;
	ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(sockfd_conn, (void *)ack_pkt);	

}
int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int sockfd_conn = sockfd->sockfd;
	int err = connect(sockfd_conn, addr, addrlen);
	if(err)
		return err;

	tcp_packet_t *syn_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_pkt->ubuf = NULL;
	syn_pkt->ulen = 0;
	syn_pkt->uflags = 0;
	syn_pkt->gt_flags |= SYN_FLAG;

	gt_send_size(sockfd_conn, (void *)syn_pkt);
//SYN is sent at this point

	tcp_packet_t *syn_ack_pkt = NULL;
	gt_recv_size(sockfd_conn, &syn_ack_pkt);
	assert((syn_ack_pkt->gt_flags & SYN_FLAG) && (syn_ack_pkt->gt_flags & ACK_FLAG));
//SYN, ACK is received at this point

	tcp_packet_t *ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	ack_pkt->ubuf = NULL;
	ack_pkt->ulen = 0;
	ack_pkt->uflags = 0;
	ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(sockfd_conn, (void *)ack_pkt);

	return err;
}

sock_descriptor_t * gt_accept(sock_descriptor_t *sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	sock_descriptor_t * new_sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	new_sockfd->sockfd = accept(sockfd->sockfd, addr, addrlen);
	new_sockfd->data = NULL;
	new_sockfd->offset = 0;
	new_sockfd->length = 0;

	if(new_sockfd->sockfd < 0)
		return new_sockfd;

//#ifdef __SERVER
	//pthread_create
//#endif

	//recv syn packet
	tcp_packet_t *syn_pkt = NULL;
	gt_recv_size(new_sockfd->sockfd, &syn_pkt);
	assert(syn_pkt->gt_flags & SYN_FLAG);

	//send syn-ack 
	tcp_packet_t *syn_ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_ack_pkt->ubuf = NULL;
	syn_ack_pkt->ulen = 0;
	syn_ack_pkt->uflags = 0;
	syn_ack_pkt->gt_flags |= SYN_FLAG;
	syn_ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(new_sockfd->sockfd, (void *)syn_ack_pkt);

	//recv ack packet
	tcp_packet_t *ack_pkt = NULL;
	gt_recv_size(new_sockfd->sockfd, &ack_pkt);
	assert(ack_pkt->gt_flags & ACK_FLAG);

	return new_sockfd;
}

ssize_t gt_send(sock_descriptor_t *sockfd, const void *buf, size_t len, int flags) {
	tcp_packet_t *send_pkt = (tcp_packet_t *) calloc(1, sizeof(tcp_packet_t));
	send_pkt->ubuf = (char *) malloc(len * sizeof(char));
	memcpy(send_pkt->ubuf, buf, len);
	send_pkt->ulen = len;
	send_pkt->uflags = flags;
	send_pkt->gt_flags = 0;
	return gt_send_size(sockfd->sockfd,send_pkt);
}

ssize_t gt_recv(sock_descriptor_t *sockfd, void *buf, size_t len, int flags) {
	/* check if we have anything to return from buffer */
	ssize_t available = sockfd->length - sockfd->offset;
	if(available <= 0)
	{
		/* we don't have any data in the buffer. 
		 * So we get the data, put it in buffer and return the required amount */
		tcp_packet_t *pkt = NULL;
		gt_recv_size(sockfd->sockfd, &pkt);
		sockfd->data = (char *) malloc(pkt->ulen * sizeof(char));
		sockfd->length = pkt->ulen;
		sockfd->offset = 0;
		memcpy(sockfd->data, pkt->ubuf, pkt->ulen);
	}

	/* we can return something from the buffer now.*/
	available = sockfd->length - sockfd->offset;
	ssize_t response_size = (available <= len) ? available : len;      // min(available, request);
	char *data = NULL;
	if(response_size > 0)
	{
		memcpy(buf, sockfd->data + sockfd->offset, response_size);
		sockfd->offset += response_size;
		if(sockfd->offset >= sockfd->length)
		{
			free(sockfd->data);
			sockfd->data = NULL;
			sockfd->offset = 0;
			sockfd->length = 0;
		}
	}

	return response_size;
}

int gt_close(sock_descriptor_t *sockfd) 
{
	/* Dummy close implementation for now to get things working.
	 * TODO : Implement connection teardown FSM here */
	if((sockfd->length - sockfd->offset > 0) && (sockfd->data))
	{
		free(sockfd->data);
		sockfd->length = 0;
		sockfd->offset = 0;
	}
	return close(sockfd->sockfd);
}
