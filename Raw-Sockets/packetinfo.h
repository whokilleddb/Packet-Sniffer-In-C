#include <stdlib.h>
#include <stdio.h>
#include <linux/ip.h>

#include "modules.h"

// Print String In Hex
void HEX_P(FILE *fd, char *mesg, unsigned char *p, int len)
{
    fprintf(fd, mesg);
    while(len--)
    {
        fprintf(fd, "%.2X ",*p);
        p++;
    }
    fprintf(fd, "\n");
}

void PRINT_PACKET_INFO(unsigned char* buffer, int size)
{
    struct ethhdr *ethernet_header;
    
    ++total;


    if(size>sizeof(struct ethhdr))
    {
        fprintf(logfile,"\n----------------- Packet -----------------\n");
        fprintf(stdout,"\n"CYAN("-----------------")MAGENTA(" Packet ")CYAN("-----------------")"\n");
        ethernet_header=(struct ethhdr *)buffer;
        
        // Print To String
        fprintf(stdout,CYAN("|- ") YELLOW("Source Address") " : " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Destination Address") " : " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Protocol") " : " GREEN("%d") "\n",ethernet_header->h_proto);

        // Save To File
        fprintf(logfile,"|- Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(logfile,"|- Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(logfile,"|- Protocol : %d\n",ethernet_header->h_proto);
    }
    else
    {
        ++undefined;
        fprintf(logfile,"\n-------------------------------\n");
        fprintf(logfile,"[-] Did Not Recv A Valid Packet\n");
        fprintf(stderr,"\n-------------------------------\n");
        fprintf(stderr,"["RED("-")"] Did Not Recv A Valid Packet\n");
    }
}