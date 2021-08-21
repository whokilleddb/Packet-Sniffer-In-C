#include "globals.h"

// Print Colors
#define RED(string)     "\x1b[31m" string "\x1b[0m"
#define GREEN(string)   "\x1b[32m" string "\x1b[0m"
#define YELLOW(string)  "\x1b[33m" string "\x1b[0m"
#define BLUE(string)    "\x1b[34m" string "\x1b[0m"
#define MAGENTA(string) "\x1b[35m" string "\x1b[0m"
#define CYAN(string)    "\x1b[36m" string "\x1b[0m"

int CHECK_WIRELESS(const char* ifname, char* protocol)
{
    int sock = -1;
    struct iwreq pwrq;
    memset(&pwrq, 0, sizeof(pwrq));
    strncpy(pwrq.ifr_name, ifname, IFNAMSIZ);
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        fprintf(stderr,"["RED("-")"]" "Socket Initialization Failed\n");
        return 0;
    }

    /*ioctl(fd, SIOCGIWNAME) returns the wireless extension protocol version, which is only available on interfaces that are wireless
    
    Definition:
    #define SIOCGIWNAME 0x8B01 -> get name == wireless protocol
    
    SIOCGIWNAME is used to verify the presence of Wireless Extensions.
    Common values : "IEEE 802.11-DS", "IEEE 802.11-FH", "IEEE 802.11b"
    */

    if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1)
    {
        if (protocol)
        {
            strncpy(protocol, pwrq.u.name, IFNAMSIZ);
        }
        close(sock);
        return 1;
    }
    close(sock);
    return 0;
}

// List all available network interfaces
int GET_INTERFACES()
{
    struct ifaddrs *addresses;
    struct ifaddrs *address;

    if (getifaddrs(&addresses) == -1)
    {
        fprintf(stderr,"[" RED("-") "]" RED("getifaddrs") "failed\n");
        return -1;
    }
    address = addresses;

    fprintf(stdout,"\n" CYAN("==========")MAGENTA("Available Devices")CYAN("==========")"\n");

    while(address)
    {
        char addr[INET6_ADDRSTRLEN]={};
        char protocol[IFNAMSIZ]={};

        int family = address->ifa_addr->sa_family;      // Get Address Family
        if (family == AF_INET || family == AF_INET6)
        {
            fprintf(stdout,GREEN("%s") "\t", address->ifa_name); // Print Device Name
            if (family == AF_INET)                      // Check IP Address Type
            {
                fprintf(stdout,YELLOW("%s") "\t","IPv4");
                struct sockaddr_in *in = (struct sockaddr_in*) address->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, addr, INET_ADDRSTRLEN);
            }
            else
            {
                fprintf(stdout,YELLOW("%s") "\t","IPv6");
                struct sockaddr_in6 *in6 = (struct sockaddr_in6*) address->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
            }

            if (CHECK_WIRELESS(address->ifa_name,protocol))
            {
                fprintf(stdout,RED("%s") " (%s)\n",addr,protocol);
            }
            else
            {
                fprintf(stdout,RED("%s") "\n",addr);
            }
        }
        address = address->ifa_next;    // Move To The Next Interface
    }

    freeifaddrs(addresses);
    return 0;
}