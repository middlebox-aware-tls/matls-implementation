/**
 * @file common.h
 * @author Hyunwoo Lee
 * @date May 1 2018
 * @brief The definitions for a connection
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <netdb.h>

int open_connection(const char *hostname, int port);

#endif /* __COMMON_H__ */
