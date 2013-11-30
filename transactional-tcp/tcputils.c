#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

#include "tcp.h"
#include "tcputils.h"

size_t gt_send_size(int sockfd, tcp_packet_t *packet) 
{
	size_t tosend, totalsent, sent;
	/* send size of data. We don't need to send sizeof header as its known at compile time */
	send(sockfd, (void *) &(packet->ulen), sizeof(size_t), 0);

	/* send header first */
	tosend =  sizeof(tcp_packet_t);
	totalsent = 0;
	sent = 0;
	while(totalsent < tosend)
	{
		sent = send(sockfd, (void *) (((char *)packet) + totalsent), (tosend - totalsent), 0);
		totalsent += sent;
	}

	/* now send the data. This is needed as our packet holds only a pointer to data,
	   and thus does not serialize it */
	tosend =  packet->ulen;
	totalsent = 0;
	sent = 0;
	while(totalsent < tosend)
	{
		sent = send(sockfd, (void *) (((char *)packet->ubuf) + totalsent), (tosend - totalsent), 0);
		totalsent += sent;
	}

	/* return only counter of user data. Its implicit that header will be sent */
	return totalsent;

}
size_t gt_recv_size(int sockfd, tcp_packet_t **packet) 
{
	size_t torecv, totalrcvd, rcvd, udata_len;;
	/* receive size of user data */
	recv(sockfd, &udata_len, sizeof(size_t), 0);

	/* allocate packet */
	*packet = (tcp_packet_t *) malloc(sizeof(tcp_packet_t));

	/* first receive the header */
	torecv = sizeof(tcp_packet_t);
	totalrcvd = 0;
	rcvd = 0;
	while(totalrcvd < torecv)
	{
      
     rcvd = recv(sockfd, (void *) (((char *) *packet) + totalrcvd), (torecv - totalrcvd), 0);
	   if(rcvd == 0) {
         (*packet)->ulen = 0;
         (*packet)->ubuf = NULL;
         return rcvd;
     }    
     totalrcvd += rcvd;
	}

	/* allocate data */
	torecv = udata_len;
	(*packet)->ubuf = (char *) malloc(torecv * sizeof(char));
  (*packet)->ulen = udata_len;
	/* now receive the data */
	totalrcvd = 0;
	rcvd = 0;
	while(totalrcvd < torecv)
	{
		rcvd = recv(sockfd, (void *) (((char *) (*packet)->ubuf) + totalrcvd), (torecv - totalrcvd), 0);
		totalrcvd += rcvd;
	}

	/* return the sizeof user data recvd. Its implicit that header will be received */
	return totalrcvd;
}