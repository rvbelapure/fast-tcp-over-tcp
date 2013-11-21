#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "tcp.h"}
#include "tcputils.h"

int token_verify(tcp_packet_t *syn_pkt){
	//should check mutex based allowed connection number
	//if limit exceed return error
}

void *handshake_func(handshake_params_t *hs_param){

	//recv syn + data packet
	tcp_packet_t *syn_pkt = NULL;
	gt_recv_size(hs_sockfd->sockfd, &syn_pkt);
	assert(syn_pkt->gt_flags & SYN_FLAG);
	
	int err = token_verify(syn_pkt);
	if(err)
		return err;
	//if return has error due to limit notify ???
	//if token failed would return work

	pthread_t app_thread;

	//how to keep data from syn_pkt in app_func_params ? TODO

	//start sending data in parallel swapn a send receive thread
	int err = pthread_create(&app_thread, NULL, hs_param->app_func, hs_params->app_func_params);
	if(err)
		return err;

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
	
	//would assert fail means handshake failed ???
	//have to send signal to the app_thread in failed case and then continue

	close(hs_param->hs_sockfd->sockfd);

	//malloc cleanup
	free(hs_param->hs_sockfd);
	free(hs_param);

	return; // all good handshake is sucessful


}

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

	return err;
}

sock_descriptor_t * gt_accept(sock_descriptor_t *sockfd, struct sockaddr *addr, socklen_t *addrlen, void *app_func, void *app_func_params) 
{
	sock_descriptor_t * app_sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	app_sockfd->sockfd = accept(sockfd->sockfd, addr, addrlen);
	app_sockfd->data = NULL;
	app_sockfd->offset = 0;
	app_sockfd->length = 0;

	if(app_sockfd->sockfd < 0)
		return app_sockfd;

	sock_descriptor_t * hs_sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	hs_sockfd->sockfd = accept(sockfd->sockfd, addr, addrlen);
	hs_sockfd->data = NULL;
	hs_sockfd->offset = 0;
	hs_sockfd->length = 0;

	if(hs_sockfd->sockfd < 0)
		return hs_sockfd;

	//Thread data set
	handshake_params_t *hs_params = (handshake_params_t *) malloc(sizeof(handshake_params_t));
	hs_params->hs_sockfd = hs_sockfd;
	hs_params->app_sockfd = app_sockfd;
	hs_params->app_func = app_func;
	hs_params->app_func_params = app_func_params;

	pthread_t handshake_thread;

	int err = pthread_create(&handshake_thread, NULL, handshake_func, hs_params);
	if(err)
		return err;

	return;
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
