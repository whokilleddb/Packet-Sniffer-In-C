#include "globals.h"

// Print Colors
#define RED(string)     "\x1b[31m" string "\x1b[0m"
#define GREEN(string)   "\x1b[32m" string "\x1b[0m"
#define YELLOW(string)  "\x1b[33m" string "\x1b[0m"
#define BLUE(string)    "\x1b[34m" string "\x1b[0m"
#define MAGENTA(string) "\x1b[35m" string "\x1b[0m"
#define CYAN(string)    "\x1b[36m" string "\x1b[0m"

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

    fprintf(stdout,CYAN("=======")MAGENTA("Available Devices")CYAN("=======")"\n");

    while(address)
    {
        char addr[INET6_ADDRSTRLEN]={};
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
            fprintf(stdout,RED("%s") "\n",addr);
        }
        address = address->ifa_next;    // Move To The Next Interface
    }

    freeifaddrs(addresses);
    return 0;
}