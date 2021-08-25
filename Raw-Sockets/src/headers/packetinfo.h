#include "modules.h"
#include "miscellaneous.h"

// Print TCP Packet
void PRINT_TCP_PACKET(unsigned char *buffer, int len)
{
    struct tcphdr *tcph = (struct tcphdr *)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
    if (len<(sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(tcph))) 
    {
        INVALID_CAPTURE("TCP",logfile,stdout);
    }
    else
    {
        fprintf(stdout,CYAN("---------------")" " MAGENTA("TCP Packet")" " CYAN("---------------")"\n");
        fprintf(logfile,"--------------- TCP Packet ---------------\n");

        fprintf(stdout,CYAN("|-") " " YELLOW("Source Port") ": " GREEN("%u")"\n", ntohs(tcph->source));
        fprintf(logfile,"|- Source Port: %u\n", ntohs(tcph->source));
        
        fprintf(stdout,CYAN("|-") " " YELLOW("Destination Port") ": " GREEN("%u")"\n", ntohs(tcph->dest));
        fprintf(logfile,"|- Destination Port: %u\n", ntohs(tcph->dest));

        fprintf(stdout,CYAN("|-") " " YELLOW("Sequence Number") ": " GREEN("%u") "\n",ntohl(tcph->seq));
        fprintf(logfile,"|- Sequence Number: %u\n",ntohl(tcph->seq));
        
        fprintf(stdout,CYAN("|-") " " YELLOW("Acknowledge Number") ": " GREEN("%u")"\n",ntohl(tcph->ack_seq));
        fprintf(logfile,"|- Acknowledge Number: %u\n",ntohl(tcph->ack_seq));

        fprintf(stdout,CYAN("|-")" " YELLOW("TCP Header Length") ": " GREEN("%d") " " BLUE("DWORDS") " " YELLOW("or") " " GREEN("%d") " " BLUE("Bytes") "\n",(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
        fprintf(logfile,"|- TCP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);  
   
        fprintf(stdout,CYAN("|-") " " YELLOW("CWR Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph->cwr);
        fprintf(logfile,"|- CWR Flag:    %d\n",(unsigned int)tcph->cwr);

        fprintf(stdout,CYAN("|-") " " YELLOW("ECN Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph->ece);
        fprintf(logfile,"|- ECN Flag:    %d\n",(unsigned int)tcph->ece);

        fprintf(stdout,CYAN("|-") " "YELLOW("Urgent Flag") ": "GREEN("%d")"\n",(unsigned int)tcph->urg);
        fprintf(logfile,"|- Urgent Flag: %d\n",(unsigned int)tcph->urg);

        fprintf(stdout,CYAN("|-") " "YELLOW("Ack Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph->ack);
        fprintf(logfile,"|- Ack Flag:    %d\n",(unsigned int)tcph->ack);

        fprintf(stdout,CYAN("|-") " "YELLOW("Push Flag") ":   "GREEN("%d")"\n",(unsigned int)tcph->psh);
        fprintf(logfile,"|- Push Flag:   %d\n",(unsigned int)tcph->psh);

        fprintf(stdout,CYAN("|-") " "YELLOW("Reset Flag") ":  "GREEN("%d")"\n",(unsigned int)tcph->rst);
        fprintf(logfile,"|- Reset Flag:  %d\n",(unsigned int)tcph->rst);

        fprintf(stdout,CYAN("|-") " "YELLOW("Syn Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph->syn);
        fprintf(logfile,"|- Syn Flag:    %d\n",(unsigned int)tcph->syn);

        fprintf(stdout,CYAN("|-") " "YELLOW("Fin Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph->fin);
        fprintf(logfile,"|- Fin Flag:    %d\n",(unsigned int)tcph->fin);

        fprintf(stdout,CYAN("|-") " "YELLOW("Window") ": "GREEN("%d")"\n",(unsigned int)tcph->window);
        fprintf(logfile,"|- Window: %d\n",ntohs(tcph->window));

        fprintf(stdout,CYAN("|-") " "YELLOW("Checksum") ": "GREEN("%d")"\n",(unsigned int)tcph->check);
        fprintf(logfile,"|- Checksum: %d\n",ntohs(tcph->check));

        fprintf(stdout,CYAN("|-") " "YELLOW("Urgent Pointer") ": "GREEN("%d")"\n",(unsigned int)tcph->urg_ptr);
        fprintf(logfile,"|- Urgent Pointer: %d\n",tcph->urg_ptr);


        HEX_P(stdout,CYAN("|-") " "YELLOW("Payload") ": \n",(unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(tcph)),len);
        HEX_P(logfile,"|- Payload:\n",(unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(tcph)),len);
    }
}

// Print ICMP Packet
void PRINT_ICMP_PACKET(unsigned char *buffer, int len)
{
    struct icmphdr *icmph = (struct icmphdr *)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
    if (len < (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(icmph)))
    {
        INVALID_CAPTURE("ICMP",logfile,stdout);
    }
    else
    {
        fprintf(stdout,CYAN("------------------")" " MAGENTA("ICMP")" " CYAN("------------------")"\n");
        fprintf(logfile,"------------------ ICMP ------------------\n");

        fprintf(stdout,CYAN("|-") " " YELLOW("Type") ": " GREEN("%d") " (" BLUE("%s") ")" "\n",(unsigned int)(icmph->type),GET_ICMP_PROTO((unsigned int)(icmph->type)));
        fprintf(logfile,"|- Type: %d (%s)\n",(unsigned int)(icmph->type),GET_ICMP_PROTO((unsigned int)(icmph->type)));

        fprintf(stdout,CYAN("|-") " "YELLOW("Code") ": " GREEN("%d") "\n", (unsigned int)(icmph->code));
        fprintf(logfile,"|- Code: %d\n", (unsigned int)(icmph->code));        

        fprintf(stdout,CYAN("|-") " " YELLOW("Checksum") ": " GREEN("%d") "\n",ntohs(icmph->checksum));
        fprintf(logfile,"|- Checksum : %d\n",ntohs(icmph->checksum));

        HEX_P(stdout,CYAN("|-") " "YELLOW("Packet Dump") ": \n",(unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)),len);
        HEX_P(logfile,"|- Packet Dump :\n",(unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)),len);
    }
}

// Print IP Header
unsigned int PRINT_IP_PACKET(unsigned char *buffer, int len)
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

    fprintf(stdout,CYAN("|-") " " YELLOW("Protocol") ": " GREEN("%d") " (" BLUE("%s") ")" "\n",(unsigned int)iph->protocol,GET_IP_PROTO((unsigned int)iph->protocol));
    fprintf(logfile,"|- Protocol: %d (%s)\n",(unsigned int)iph->protocol,GET_IP_PROTO((unsigned int)iph->protocol));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Checksum") ": " GREEN("%d") "\n",ntohs(iph->check));
    fprintf(logfile,"|- Checksum: %d\n",ntohs(iph->check));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Source IP")": "GREEN("%s") "\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"|- Source IP: %s\n",inet_ntoa(source.sin_addr));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Destination IP")": "GREEN("%s") "\n",inet_ntoa(dest.sin_addr));
    fprintf(logfile,"|- Destination IP: %s\n",inet_ntoa(dest.sin_addr));

    return (unsigned int)iph->protocol;
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
        fprintf(stdout,CYAN("|- ") YELLOW("Source Address") ": " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Destination Address") ": " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Protocol") ": " GREEN("%d") " ("BLUE("%s")")" "\n",ethernet_header->h_proto,GET_ETHER_PROTO((ntohs(ethernet_header->h_proto))));

        // Save To File
        fprintf(logfile,"|- Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2],ethernet_header->h_source[3],ethernet_header->h_source[4],ethernet_header->h_source[5]);
        fprintf(logfile,"|- Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2],ethernet_header->h_dest[3],ethernet_header->h_dest[4],ethernet_header->h_dest[5]);
        fprintf(logfile,"|- Protocol : %d (%s)\n",ethernet_header->h_proto,GET_ETHER_PROTO((ntohs(ethernet_header->h_proto))));

        // Print IP Packet
        if(size>=(sizeof(struct ethhdr)+sizeof(struct iphdr)) && (ethernet_header->h_proto)==8)
        {
            unsigned int IP_PROTO;
            fprintf(stdout,CYAN("-------------------")" " MAGENTA("IP")" " CYAN("-------------------")"\n");
            fprintf(logfile,"------------------- IP -------------------\n");
            IP_PROTO=PRINT_IP_PACKET(buffer,size);
            switch(IP_PROTO)
            {
                case  IPPROTO_ICMP:
                    ++icmp;
                    PRINT_ICMP_PACKET(buffer,size);
                    break;
                case  IPPROTO_TCP:
                    ++tcp;
                    PRINT_TCP_PACKET(buffer,size);
                    break;
                case IPPROTO_UDP:
                    ++udp;
                    break;
                default:
                    ++others;
                    fprintf(stdout,CYAN("|-") " " YELLOW("Unsuported Protocol")" " MAGENTA(":(")"\n");
                    fprintf(logfile,"|- Unsuported Protocol :(\n");
                    HEX_P(stdout,YELLOW("|-") " " RED("Complete Packet Dump") "\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
                    HEX_P(logfile,"|- Complete Packet Dump\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
                    break;
            }
        }
        // Print Un-Supported Protocols
        else if (size>=(sizeof(struct ethhdr)+sizeof(struct iphdr)) && (ethernet_header->h_proto)!=8)
        {
            ++others;
            fprintf(stdout,CYAN("|-") " " YELLOW("Unsuported Protocol")" " MAGENTA(":(")"\n");
            fprintf(logfile,"|- Unsuported Protocol :(\n");
            HEX_P(stdout,YELLOW("|-") " " RED("Complete Packet Dump") "\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
            HEX_P(logfile,"|- Complete Packet Dump\n", (unsigned char*)(buffer+sizeof(struct ethhdr)),size);
        }
        // Invalid IP Packets
        else
        {
            ++undefined;
            INVALID_CAPTURE("IP",logfile,stdout);
        }        
    }
    // Print Invalid Ethernet Packets
    else
    {

        ++undefined;
        INVALID_CAPTURE("Ethernet",logfile,stdout);
    }
}