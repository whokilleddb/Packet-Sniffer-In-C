#include "modules.h"

// Print IP Header
void PRINT_IP_PACKET(unsigned char *buffer, int len)
{
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    struct iphdr *iph=(struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    /* Structure Of sockaddr_in
    struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
    };

    struct in_addr {
        unsigned long s_addr;  // load with inet_aton()
    };
    */
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(stdout,CYAN("|-") " " MAGENTA("IP Headers")"\n");
    fprintf(logfile,"|- IP Headers\n");

    fprintf(stdout, CYAN("|-") " " YELLOW("Version") ": " GREEN("IPv%d")"\n",(unsigned int)iph->version);   
    fprintf(logfile, "|- Version: IPv%d\n",(unsigned int)iph->version);       
    
    fprintf(stdout,CYAN("|-")" " YELLOW("IP Header Length") ": " GREEN("%d") " " BLUE("DWORDS") " " YELLOW("or") " " GREEN("%d") " " BLUE("Bytes") "\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile,"|- IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);

	fprintf(stdout,CYAN("|-") " " YELLOW("Type Of Service") ": " GREEN("%d") "\n",(unsigned int)iph->tos);
	fprintf(logfile,"|- Type Of Service   : %d\n",(unsigned int)iph->tos);

    fprintf(stdout,CYAN("|-") " " YELLOW("Total Length") ": " GREEN("%d") " " BLUE("Bytes") YELLOW("(Size of Packet)") "\n",ntohs(iph->tot_len));
    fprintf(logfile,"|- Total Length: %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));

    fprintf(stdout,CYAN("|-") " " YELLOW("Identification") ": " GREEN("%d") "\n",ntohs(iph->id));
    fprintf(logfile,"|- Identification: %d\n",ntohs(iph->id));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("TTL")": " GREEN("%d")"\n",(unsigned int)iph->ttl);
    fprintf(logfile,"|- TTL: %d\n",(unsigned int)iph->ttl);

    fprintf(stdout,CYAN("|-") " " YELLOW("Protocol") ": " GREEN("%d")"\n",(unsigned int)iph->protocol);
    fprintf(logfile,"|- Protocol: %d\n",(unsigned int)iph->protocol);
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Checksum") ": " GREEN("%d") "\n",ntohs(iph->check));
    fprintf(logfile,"|- Checksum: %d\n",ntohs(iph->check));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Source IP")": "GREEN("%s") "\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"|- Source IP: %s\n",inet_ntoa(source.sin_addr));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Destination IP")": "GREEN("%s") "\n",inet_ntoa(dest.sin_addr));
    fprintf(logfile,"|- Destination IP: %s\n",inet_ntoa(dest.sin_addr));

}

// Print Information About The Packet
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
        fprintf(stdout,CYAN("----------------")" " MAGENTA("Ethernet")" " CYAN("----------------")"\n");
        fprintf(logfile,"---------------- Ethernet ----------------\n");
        fprintf(stdout,CYAN("|- ") YELLOW("Source Address") " : " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Destination Address") " : " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Protocol") " : " GREEN("%s") "\n",ethernet_header->h_proto==8?"IPv4":ethernet_header->h_proto==ETHERTYPE_ARP?"ARP":ethernet_header->h_proto==IPV6_IDENTIFIER?"IPv6":"Undefined");

        // Save To File
        fprintf(logfile,"|- Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(logfile,"|- Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(logfile,"|- Protocol : %s\n",ethernet_header->h_proto==8?"IP":ethernet_header->h_proto==ETHERTYPE_ARP?"ARP":(int)ethernet_header->h_proto==IPV6_IDENTIFIER?"IPv6":"Undefined");

        // Print IP Packet
        if(size>=(sizeof(struct ethhdr)+sizeof(struct iphdr)) && (ethernet_header->h_proto)==8)
        {
            fprintf(stdout,CYAN("-------------------")" " MAGENTA("IP")" " CYAN("-------------------")"\n");
            fprintf(logfile,"------------------- IP -------------------\n");
            PRINT_IP_PACKET(buffer,size);
            
        }
        // Print Un-Supported Protocols
        else if (size>=(sizeof(struct ethhdr)+sizeof(struct iphdr)) && (ethernet_header->h_proto)!=8)
        {
            ++others;
            fprintf(stdout,YELLOW("|-") " " RED("Protocol Not Supported") "\n");
            fprintf(logfile,"|- Protocol Not Supported\n");
            
            HEX_P(stdout,YELLOW("|-") " " RED("Complete Packet Dump") "\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
            HEX_P(logfile,"|- Complete Packet Dump\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
        }
        // Invalid IP Packets
        else
        {
            INVALID_CAPTURE("IP");
        }        
    }
    // Print Invalid Ethernet Packets
    else
    {
        INVALID_CAPTURE("Ethernet");
    }
}