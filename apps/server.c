#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "../tcp-base/tcp.h"

int main( int argc, char *argv[] )
{
    sock_descriptor_t *sockfd, *newsockfd;
    int portno, clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int  n;

    /* First call to socket() function */
    sockfd = gt_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        perror("ERROR opening socket");
        exit(1);
    }
    /* Initialize socket structure */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 5001;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    /* Now bind the host address using bind() call.*/
//    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    if (gt_bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR on binding");
        exit(1);
    }

    /* Now start listening for the clients, here process will
     *     * go in sleep mode and will wait for the incoming connection
     *         */
    //listen(sockfd,5);
    gt_listen(sockfd,5);
    clilen = sizeof(cli_addr);

    /* Accept actual connection from the client */
    //newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    newsockfd = gt_accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    if (newsockfd < 0) 
    {
        perror("ERROR on accept");
        exit(1);
    }
    /* If connection is established then start communicating */
    bzero(buffer,256);
    //n = read( newsockfd,buffer,255 );
    //passing 0 for the flags
    n = gt_recv( newsockfd,buffer,255,0 );
    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(1);
    }
    printf("Here is the message: %s\n",buffer);

    /* Write a response to the client */
    //n = write(newsockfd,"I got your message",18);
    n = gt_send(newsockfd,"I got your message",18, 0);
    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(1);
    }
    return 0; 
}

