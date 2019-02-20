#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "logger.h"

#define FAIL    -1

int open_listener(int port);

// Origin Server Implementation
int main(int count, char *strings[])
{  
	int server, client, sent = 0, rcvd = 0;
	char *portnum, *cert, *key;
	const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 72\r\n"
		"\r\n"
		"<html><title>Test</title><body><h1>Test Alice's Page!</h1></body></html>";
	int response_len = strlen(response);

	if ( count != 2 )
	{
		printf("Usage: %s <portnum> \n", strings[0]);
		exit(0);
	}

	portnum = strings[1];

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	unsigned char buf[2048];
	socklen_t len = sizeof(addr);

	while ((client = accept(server, (struct sockaddr *)&addr, &len)))
	{
		printf("New Connection\n");

		rcvd = read(client, buf, sizeof(buf));
    printf("Request (%d): %s\n", rcvd, buf);
		sent = write(client, response, response_len);

		printf("SERVER: HTTP Response Length: %d\n", response_len);
		printf("SERVER: Send the HTTP Test Page Success: %d\n", sent);

		close(client);
	}

	close(server);          /* close server socket */

	return 0;
}

int open_listener(int port)
{   
  int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}
