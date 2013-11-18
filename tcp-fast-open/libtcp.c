#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "tcp.h"
#include "tcputils.h"
#include "pkt_queue.h"

sock_buffer_t primary_buffer;

void gt_init()
{
	sock_buffer_init(&primary_buffer);
}

int gt_listen(int sockfd, int backlog) {
	return listen(sockfd, backlog);
}
int gt_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	return bind(sockfd, addr, addrlen);
}
int gt_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int sockfd_conn = sockfd;
	connect(sockfd, addr, addrlen);

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

	return sockfd_conn;
}

int gt_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	int new_sockid = accept(sockfd, addr, addrlen);

	//recv syn packet
	tcp_packet_t *syn_pkt = NULL;
	gt_recv_size(new_sockid, &syn_pkt);
	assert(syn_pkt->gt_flags & SYN_FLAG);

	//send syn-ack 
	tcp_packet_t *syn_ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_ack_pkt->ubuf = NULL;
	syn_ack_pkt->ulen = 0;
	syn_ack_pkt->uflags = 0;
	syn_ack_pkt->gt_flags |= SYN_FLAG;
	syn_ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(new_sockid, (void *)syn_ack_pkt);

	//recv ack packet
	tcp_packet_t *ack_pkt = NULL;
	gt_recv_size(new_sockid, &ack_pkt);
	assert(ack_pkt->gt_flags & ACK_FLAG);

	return new_sockid;
	
}

ssize_t gt_send(int sockfd, const void *buf, size_t len, int flags) {
	tcp_packet_t *send_pkt = (tcp_packet_t *) calloc(1, sizeof(tcp_packet_t));
	send_pkt->ubuf = (char *) malloc(len * sizeof(char));
	memcpy(send_pkt->ubuf, buf, len);
	send_pkt->ulen = len;
	send_pkt->uflags = flags;
	send_pkt->gt_flags = 0;
	return gt_send_size(sockfd,send_pkt);
}

ssize_t gt_recv(int sockfd, void *buf, size_t len, int flags) {
	/* check if we have anything to return from buffer */
	ssize_t available = sock_buffer_can_read(&primary_buffer, sockfd);
	if(available <= 0)
	{
		/* we don't have any data in the buffer. 
		 * So we get the data, put it in buffer and return the required amount */
		tcp_packet_t *pkt = NULL;
		gt_recv_size(sockfd, &pkt);
		sock_buffer_put_data(&primary_buffer, sockfd, pkt->ulen, pkt->ubuf);
	}

	/* in most cases, i.e. when response_size > 0, 
	 * we can return something from the buffer now.*/
	ssize_t response_size = 0;
	char * data = sock_buffer_get_data(&primary_buffer, sockfd, len, &response_size);
	if(response_size > 0)
	{
		memcpy(buf, data, response_size);
		free(data);
	}
	return response_size;
}

int gt_close(int sockfd) 
{
	/* Dummy close implementation for now to get things working.
	 * TODO : Implement connection teardown FSM here */
	close(sockfd);
}
