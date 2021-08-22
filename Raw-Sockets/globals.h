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

#define MTU 65536
#define LOGFILE_NAME "sniff.log"

int sock_raw;                                          // Socket Descriptor
FILE *logfile;                                         // Logfile To Store Data
struct ifreq INTERFACE;                                // Interface To Sniff On
struct sockaddr_ll sll;                                // Contain Socket Information
unsigned char *buffer;                                 // Store Packet Information
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,undefined=0,i,j;    // 
struct sockaddr_in source,dest;

// Print Colors
#define RED(string)     "\x1b[31m" string "\x1b[0m"
#define GREEN(string)   "\x1b[32m" string "\x1b[0m"
#define YELLOW(string)  "\x1b[33m" string "\x1b[0m"
#define BLUE(string)    "\x1b[34m" string "\x1b[0m"
#define MAGENTA(string) "\x1b[35m" string "\x1b[0m"
#define CYAN(string)    "\x1b[36m" string "\x1b[0m"