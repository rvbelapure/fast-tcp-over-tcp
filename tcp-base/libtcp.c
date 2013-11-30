#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "tcp.h"
#include "tcputils.h"

sock_descriptor_t * gt_socket(int domain, int type, int protocol)
{
	sock_descriptor_t * sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	sockfd->sockfd = socket(domain, type, protocol);
	sockfd->data = NULL;
	sockfd->offset = 0;
	sockfd->length = 0;
	return sockfd;
}

int gt_listen(sock_descriptor_t *sockfd, int backlog) {
	return listen(sockfd->sockfd, backlog);
}
int gt_bind(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	return bind(sockfd->sockfd, addr, addrlen);
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

	free(syn_pkt);
	free(syn_ack_pkt);
	free(ack_pkt);
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
	{
		free(new_sockfd);
		return NULL;
	}

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

	free(syn_pkt);
	free(syn_ack_pkt);
	free(ack_pkt);

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
	if(sockfd == NULL)
		return -1;
	/* check if we have anything to return from buffer */
	ssize_t available = sockfd->length - sockfd->offset;
	ssize_t retval;
	if(available <= 0)
	{
		/* we don't have any data in the buffer. 
		 * So we get the data, put it in buffer and return the required amount */
		tcp_packet_t *pkt = NULL;
		retval = gt_recv_size(sockfd->sockfd, &pkt);
		sockfd->data = (char *) malloc(pkt->ulen * sizeof(char));
		sockfd->length = pkt->ulen;
		sockfd->offset = 0;
		memcpy(sockfd->data, pkt->ubuf, pkt->ulen);
		if(retval <= 0)
		{
			free(sockfd->data);
			sockfd->data = NULL;
			sockfd->offset = 0;
			sockfd->length = 0;
			return retval;
		}
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
