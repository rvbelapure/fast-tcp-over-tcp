/* To compile me in Solaris type:  gcc -o client client.c -lsocket -lnsl */
/* To compile me in Linux type:  gcc -o client client.c */

/* client.c - code for example client that uses TCP         */
/* From Computer Networks and Internets by Douglas F. Comer */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../tcp-fast-open/tcp.h"

#define closesocket      close
#define PROTOPORT        5193        /* default protocol port number */

#define EXPERIMENT_COUNT 10
#define PAGE_COUNT	 1

extern int               errno;
char   localhost[] = "localhost";    /* default host name            */
/*---------------------------------------------------------------------
 * Program:   client
 *
 * Purpose:   allocate a socket, connect to a server, and print all output
 *
 * Syntax:    client [ host [port] ]
 *
 *              host - name of a computer on which server is executing
 *              port - protocol port number server is using
 *
 * Note:      Both arguments are optional.  If no host name is specified,
 *            the client uses "localhost";  if no protocol port is
 *            specified, the client uses the default given by PROTOPORT.
 *
 *---------------------------------------------------------------------
 */
int main(int argc, char *argv[])
{
   struct  hostent  *ptrh;   /* pointer to a host table entry       */
   struct  protoent *ptrp;   /* point to a protocol table entry     */
   struct  sockaddr_in sad;  /* structure to hold server's address  */
   sock_descriptor_t*     sd;               /* socket descriptor                   */
   int     port;             /* protocol port number                */
   char    *host;            /* pointer to host name                */
   int     n;                /* number of characters read           */
   char    buf[1000];        /* buffer for data from the server     */
   char input_buf[1025];

   memset((char *)&sad,0,sizeof(sad));  /* clear sockaddr structure */
   sad.sin_family = AF_INET;            /* set family to Internet   */

   /* Check command-line argument for protocol port and extract     */
   /* port number if on is specified.  Otherwise, use the default   */
   /* port value biven by constant PROTOPORT                        */

   if (argc > 2) port = atoi(argv[2]);
   else port = PROTOPORT;
   
   if (port > 0) sad.sin_port = htons((u_short)port);
   else 
     { fprintf( stderr,"bad port number %s\n", argv[2]);
          exit(1);
     }
   
   if (argc > 1 ) host = argv[1];
   else host = localhost;

   ptrh = gethostbyname(host);
   if( ((char *)ptrh) == NULL)
     { fprintf( stderr, "invalid host:  %s\n", host);
       exit(1);
     }
   
   memcpy(&sad.sin_addr, ptrh->h_addr, ptrh->h_length);

   if ( ((int)(ptrp = getprotobyname("tcp"))) == 0)
     { fprintf( stderr, "cannot map \"tcp\" to protocol number\n");
       exit(1);
     }

   FILE *fp = fopen("web-stream.txt", "r");
   if(fp == NULL)
   {
	   perror("web-stream file");
	   exit(1);
   }

   char *stream = NULL;
   int stsize = 0;
   float y, t;
   unsigned long cookie = 0;

   struct timespec ts;
   srandom(time(NULL));

   size_t count = 0;
   while(count < EXPERIMENT_COUNT)
   {
	if(getline(&stream, &stsize, fp) == -1)
		break;

	y = atof(stream);
	t =  4.0 * (logf(32768.0) - logf(y));
	t = t < 200.0 ? t : 200.0;
	ts.tv_sec = (time_t) t;
	ts.tv_nsec = (t - (time_t) t) * 1000000000;
	free(stream);
	stream = NULL;
	nanosleep(&ts, NULL);

	sd = gt_socket(PF_INET, SOCK_STREAM, ptrp->p_proto);
	if (sd < 0)
	{ 
		perror("gt_socket");
		continue;
	}

	sprintf(input_buf, "page%ld.html", (random() % PAGE_COUNT));
	fprintf(stdout, "client : getting %s... ", input_buf);
	if (gt_connect(sd, (struct sockaddr *)&sad, sizeof(sad), &cookie, input_buf, strlen(input_buf)) < 0)
	{
		perror("gt_connect");
		gt_close(sd);
		continue;
	}

	while(gt_recv(sd, input_buf, 1024, 0) > 0);
	fprintf(stdout, "done\n");
	gt_close(sd);

	count++;
   }
   
   fclose(fp);
   return 0;   
}



