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
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define MTU 65536
#define LOGFILE_NAME "sniff.log"

int sock_raw;                       // Socket Descriptor
FILE *logfile;                      // Logfile To Store Data
struct ifreq INTERFACE;             // Interface To Sniff On
struct sockaddr_ll sll;             // Contain Socket Information
unsigned char *buffer;              // Store Packet Information