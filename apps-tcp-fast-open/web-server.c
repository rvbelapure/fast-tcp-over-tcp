/* to compile me in Linux, type:   gcc -o concurrentserver concurrentserver.c -lpthread */

/* server.c - code for example server program that uses TCP */
/* From Computer Networks and Internets by Douglas F. Comer */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "../tcp-fast-open/tcp.h"

void * serverthread(void * parm);       /* thread function prototype    */

pthread_mutex_t  mut;

#define PROTOPORT         5193          /* default protocol port number */
#define QLEN              6             /* size of request queue        */

int visits =  0;                        /* counts client connections     */

/*************************************************************************
 Program:        concurrent server

 Purpose:        allocate a socket and then repeatedly execute the folllowing:
                          (1) wait for the next connection from a client
                          (2) create a thread to handle the connection
                          (3) go back to step (1)

                 The server thread will
                          (1) update a global variable in a mutex
                          (2) send a short message to the client
                          (3) close the connection

 Syntax:         server [ port ]

                            port  - protocol port number to use

 Note:           The port argument is optional. If no port is specified,
                        the server uses the default given by PROTOPORT.

**************************************************************************
*/

main (int argc, char *argv[])
{
     struct   hostent   *ptrh;     /* pointer to a host table entry */
     struct   protoent  *ptrp;     /* pointer to a protocol table entry */
     struct   sockaddr_in sad;     /* structure to hold server's address */
     struct   sockaddr_in cad;     /* structure to hold client's address */
     sock_descriptor_t *sd, *sd2;             /* socket descriptors */
     int      port;                /* protocol port number */
     int      alen;                /* length of address */
     pthread_t  tid;             /* variable to hold thread ID */

     pthread_mutex_init(&mut, NULL);
     memset((char  *)&sad,0,sizeof(sad)); /* clear sockaddr structure   */
     sad.sin_family = AF_INET;            /* set family to Internet     */
     sad.sin_addr.s_addr = INADDR_ANY;    /* set the local IP address */

     /* Check  command-line argument for protocol port and extract      */
     /* port number if one is specfied.  Otherwise, use the default     */
     /* port value given by constant PROTOPORT                          */
    
     if (argc > 1) {                        /* if argument specified     */
                     port = atoi (argv[1]); /* convert argument to binary*/
     } else {
                      port = PROTOPORT;     /* use default port number   */
     }
     if (port > 0)                          /* test for illegal value    */
                      sad.sin_port = htons((u_short)port);
     else {                                /* print error message and exit */
                      fprintf (stderr, "bad port number %s/n",argv[1]);
                      exit (1);
     }

     /* Map TCP transport protocol name to protocol number */
     
     if ( ((int)(ptrp = getprotobyname("tcp"))) == 0)  {
                     fprintf(stderr, "cannot map \"tcp\" to protocol number");
                     exit (1);
     }

     gt_init();

     /* Create a socket */
     sd = gt_socket (PF_INET, SOCK_STREAM, ptrp->p_proto);
     if (sd < 0) {
		       perror("gt_socket");
                       exit(1);
     }

     /* Bind a local address to the socket */
     if (gt_bind(sd, (struct sockaddr *)&sad, sizeof (sad)) < 0) {
	     		perror("gt_bind");
                        exit(1);
     }

     /* Specify a size of request queue */
     if (gt_listen(sd, QLEN) < 0) {
                        perror("gt_listen");
                        exit(1);
     }

     alen = sizeof(cad);

     server_app_args_t* server_app_args = (server_app_args_t*) malloc(sizeof(server_app_args_t));
     server_app_args -> app_func_params = sd;

     /* Main server loop - accept and handle requests */
     fprintf( stderr, "Server up and running.\n");
     while (1) {

         if (gt_accept(sd, (struct sockaddr *)&cad, &alen,(void*) serverthread, server_app_args) < 0) {
	          fprintf(stderr, "accept failed\n");
            exit (1);
      	 }
     }
     gt_close(sd);
}


void * serverthread(void * parm)
{
   pthread_detach(pthread_self());
   server_app_args_t *args = (server_app_args_t *) parm;
   sock_descriptor_t* tsd;
   int tvisits;
   char     buf[1024];           /* buffer for string the server sends */
   char output_buf[1024];

   tsd = (sock_descriptor_t*) args->app_sockfd;

   pthread_mutex_lock(&mut);
        tvisits = ++visits;
   pthread_mutex_unlock(&mut);

   int tocopy = (args->datalen < 1024) ? args->datalen : 1024;
   memcpy(output_buf, args->data, tocopy);
   output_buf[tocopy] = '\0';
   printf("servicing request : %s\n", output_buf);

   sprintf(buf, "server-pages/%s", output_buf);
   FILE *fp = fopen(buf, "r");
   if(fp == NULL)
   {
	   perror(output_buf);
	   gt_close(tsd);
	   pthread_exit(NULL);
   }

   size_t size;
   while((size = fread(buf, sizeof(char), 1024, fp)) > 0)
	   gt_send(tsd, buf, size, 0);

   gt_close(tsd);
   pthread_exit(NULL);
}    
