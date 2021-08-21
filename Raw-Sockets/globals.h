#include <stdio.h>	
#include <stdlib.h>	
#include <string.h>	
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <arpa/inet.h>

#define MTU 65536
#define LOGFILE_NAME "sniff.log"

int sock_raw;
FILE *logfile;
struct sockaddr_in source, dest;