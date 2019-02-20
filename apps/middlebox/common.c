/**
 * @file common.c
 * @author Hyunwoo Lee
 * @date May 1 2018
 * @brief The function implementations
 */

#include "common.h"
#include "logs.h"

int open_connection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    MA_LOG1s("hostname", hostname);
            
    if ( (host = gethostbyname(hostname)) == NULL )
    {
          perror(hostname);
          abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);

    /////
#ifdef NO_NAGLE
    int flag = 1;
    setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif /* NO_NAGLE */
    /////

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
         close(sd);
         perror(hostname);
         abort();
    }
    return sd;
}

