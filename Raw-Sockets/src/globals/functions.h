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
#include <signal.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>

// Print Colors
#define RED(string)     "\x1b[31m" string "\x1b[0m"
#define GREEN(string)   "\x1b[32m" string "\x1b[0m"
#define YELLOW(string)  "\x1b[33m" string "\x1b[0m"
#define BLUE(string)    "\x1b[34m" string "\x1b[0m"
#define MAGENTA(string) "\x1b[35m" string "\x1b[0m"
#define CYAN(string)    "\x1b[36m" string "\x1b[0m"

