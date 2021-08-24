#include <stdlib.h>
#include <stdio.h>
#include <linux/ip.h>

#include "modules.h"

void PRINT_PACKET_INFO(unsigned char* buffer, int size)
{
    struct ethhdr *ethernet_header;
    
    ++total;


    if(size>sizeof(struct ethhdr))
    {
        fprintf(logfile,"\n================= Packet =================\n");
        fprintf(stdout,"\n"CYAN("=================")MAGENTA(" Packet ")CYAN("=================")"\n");
        ethernet_header=(struct ethhdr *)buffer;
        
        // Print To String
        fprintf(stdout,CYAN("|- ") YELLOW("Source Address") " : " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Destination Address") " : " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Protocol") " : " GREEN("%s") "\n",ethernet_header->h_proto==8?"IP":ethernet_header->h_proto==ETHERTYPE_ARP?"ARP":ethernet_header->h_proto==IPV6_IDENTIFIER?"IPv6":"Undefined");

        // Save To File
        fprintf(logfile,"|- Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(logfile,"|- Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(logfile,"|- Protocol : %s\n",ethernet_header->h_proto==8?"IP":ethernet_header->h_proto==ETHERTYPE_ARP?"ARP":(int)ethernet_header->h_proto==IPV6_IDENTIFIER?"IPv6":"Undefined");

        if(size>=(sizeof(struct ethhdr)+sizeof(struct iphdr)) && (ethernet_header->h_proto)==8)
        {
          //  struct iphdr *iph=(struct iphdr*)(buffer + sizeof(struct ethhdr));
            
        }
        else
        {
            ++others;
            fprintf(stdout,YELLOW("|-") " " RED("Protocol Not Supported") "\n");
            fprintf(logfile,"|- Protocol Not Supported\n");
            
            HEX_P(stdout,YELLOW("|-") " " RED("Complete Packet Dump") "\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
            HEX_P(logfile,"|- Complete Packet Dump\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
        }
       
        
    }
    else
    {
        ++undefined;
        fprintf(logfile,"|- Could Not Capture Full Ethernet Packet\n");
        fprintf(stderr,RED("|-")" Could Not Capture Full Ethernet Packet\n");
    }
}