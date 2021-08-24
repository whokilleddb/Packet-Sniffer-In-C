/*  This file defines the globals
    The Global Varibles and Their default values are:

    MTU - Maximum Transfer Unit - Default: 65536
    LOGFILE_NAME - Name Of TThe Log File - Default: "sniff.log"
    sock_raw - Socket Descriptor for the Raw Socket
    logfile - Handle For The Log File
    INTERFACE - Store Information About The Interface To Bind To
    sll - Struct to store information about the INTERFACE
    buffer - Store packet data

*/
#include <stdio.h>	
#include <stdlib.h>	

#define MTU 65536
#define LOGFILE_NAME "sniff.log"
#define ETHERTYPE_ARP 0x0806
#define IPV6_IDENTIFIER 56710

int sock_raw;                                          // Socket Descriptor
FILE *logfile;                                         // Logfile To Store Data
struct ifreq INTERFACE;                                // Interface To Sniff On
struct sockaddr_ll sll;                                // Contain Socket Information
unsigned char *buffer;                                 // Store Packet Information
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,undefined=0;    // 
