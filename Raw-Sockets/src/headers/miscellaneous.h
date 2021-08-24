#include <linux/in.h>
#include <linux/icmp.h>

char *GET_IP_PROTO(unsigned int proto)
{
    switch(proto)
    {
        case IPPROTO_IP:
            return "Dummy protocol for TCP";
        case IPPROTO_ICMP:
            return "Internet Control Message Protocol";
        case IPPROTO_IGMP:
            return "Internet Group Management Protocol";
        case IPPROTO_IPIP:
            return "IPIP tunnels";
        case IPPROTO_TCP:
            return "Transmission Control Protocol";
        case IPPROTO_EGP:
            return "Exterior Gateway Protocol";
        case IPPROTO_PUP:
            return "PUP Protocol";
        case IPPROTO_UDP:
            return "User Datagram Protocol";
        case IPPROTO_IDP:
            return "XNS IDP protocol";
        case IPPROTO_TP:
            return "SO Transport Protocol Class 4";
        case IPPROTO_DCCP:
            return "Datagram Congestion Control Protocol";
        case IPPROTO_IPV6:
            return "IPv6-in-IPv4 tunnelling";
        case IPPROTO_RSVP:
            return "RSVP Protocol";
        case IPPROTO_GRE:
            return "Cisco GRE tunnels";
        case IPPROTO_ESP:
            return "Encapsulation Security Payload protocol";
        case IPPROTO_AH:
            return "Authentication Header protocol";
        case IPPROTO_MTP:
            return "Multicast Transport Protocol";    
        case IPPROTO_BEETPH:
            return "IP option pseudo header for BEET";
        case IPPROTO_ENCAP:
            return "Encapsulation Header";
        case IPPROTO_PIM:
            return "Protocol Independent Multicast";
        case IPPROTO_COMP:
            return "Compression Header Protocol";
        case IPPROTO_SCTP:
            return "Stream Control Transport Protocol";
        case IPPROTO_UDPLITE:
            return "UDP-Lite";
        case  IPPROTO_MPLS:
            return "MPLS in IP";
        case IPPROTO_RAW:
            return "Raw IP packets";
        default :
            return "Unknown Protocol";
    }  
}

char *GET_ICMP_PROTO(unsigned int type)
{
    switch(type)
    {
        case ICMP_ECHOREPLY	:
            return "Echo Reply";
        case  ICMP_DEST_UNREACH :
            return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH:
            return "Source Quench";
        case ICMP_REDIRECT:
            return "Redirect";
        case ICMP_ECHO:
            return "Echo";
        case ICMP_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMP_PARAMETERPROB:
            return "Parameter Problem";
        case ICMP_TIMESTAMP	:
            return "Timestamp Request";
        case ICMP_TIMESTAMPREPLY:
            return "Timestamp Reply";
        case ICMP_INFO_REQUEST:
            return "Information Request";
        case ICMP_INFO_REPLY:
            return "Information Reply";
        case ICMP_ADDRESS:
            return "Address Mask Request";
        case ICMP_ADDRESSREPLY:
            return "Address Mask Reply";
        default:
            return "Unknown";
    }
}

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

// Invalid Packets
void INVALID_CAPTURE(char *proto, FILE *log, FILE *stream)
{
    fprintf(log,"|- Could Not Capture Full %s Packet\n",proto);
    fprintf(stream,RED("|-")" Could Not Capture Full "RED("%s")" Packet\n",proto);
}