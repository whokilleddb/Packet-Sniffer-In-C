#include <linux/in.h>
#include <linux/icmp.h>

#ifndef ETH_P_PREAUTH
#define ETH_P_PREAUTH -1
#endif 

#ifndef ETH_P_LLDP
#define ETH_P_LLDP -1
#endif 

#ifndef ETH_P_MRP
#define ETH_P_MRP -1
#endif 

#ifndef ETH_P_CFM
#define ETH_P_CFM -1
#endif 

#ifndef ETH_P_DSA_8021Q
#define ETH_P_DSA_8021Q -1
#endif 

#ifndef ETH_P_ERSPAN2
#define ETH_P_ERSPAN2 -1
#endif 

char *GET_ETHER_PROTO(uint16_t proto)
{
    switch(proto)
    {
        case ETH_P_LOOP:
            return "Ethernet Loopback packet";
        case ETH_P_PUP:
            return "Xerox PUP packet";
        case ETH_P_PUPAT:
            return "Xerox PUP Addr Trans packet";
        case ETH_P_TSN:
            return "TSN (IEEE 1722) packet";
        case ETH_P_ERSPAN2:
            return "ERSPAN version 2 (type III)";
        case ETH_P_IP:
            return "Internet Protocol packet";
        case ETH_P_X25:
            return "CCITT X.25";
        case ETH_P_ARP:
            return "Address Resolution packet";
        case ETH_P_BPQ:
            return "G8BPQ AX.25 Ethernet Packet";
        case ETH_P_IEEEPUP:
            return "Xerox IEEE802.3 PUP packet";
        case ETH_P_IEEEPUPAT:
            return "Xerox IEEE802.3 PUP Addr Trans packet";
        case ETH_P_BATMAN:
            return "B.A.T.M.A.N.-Advanced packet";
        case ETH_P_DEC:
            return "DEC Assigned proto";
        case ETH_P_DNA_DL:
            return "DEC DNA DumpLoad";
        case ETH_P_DNA_RC:
            return "DEC DNA Remote Console";
        case ETH_P_DNA_RT:
            return "DEC DNA Routing";
        case ETH_P_LAT:
            return "DEC LAT";
        case ETH_P_DIAG:
            return "DEC Diagnostics";
        case ETH_P_CUST:
            return "DEC Customer use";
        case ETH_P_SCA:
            return "DEC Systems Comms Arch";
        case ETH_P_TEB:
            return "Trans Ether Bridging";
        case ETH_P_RARP:
            return "Reverse Addr Res packet";
        case ETH_P_ATALK:
            return "Appletalk DDP";
        case ETH_P_AARP:
            return "Appletalk AARP";
        case ETH_P_8021Q:
            return "802.1Q VLAN Extended Header";
        case ETH_P_ERSPAN:
            return "ERSPAN type II";
        case ETH_P_IPX:
            return "IPX over DIX";
        case ETH_P_IPV6:
            return "IPv6 over bluebook";
        case ETH_P_PAUSE:
            return "IEEE Pause frames. See 802.3 31B";
        case ETH_P_SLOW:
            return "Slow Protocol. See 802.3ad 43B";
        case ETH_P_WCCP:
            return "Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt";
        case ETH_P_MPLS_UC:
            return "MPLS Unicast traffic";
        case ETH_P_MPLS_MC:
            return "MPLS Multicast traffic";
        case ETH_P_ATMMPOA:
            return "MultiProtocol Over ATM";
        case ETH_P_PPP_DISC:
            return "PPPoE discovery messages";
        case ETH_P_PPP_SES:
            return "PPPoE session messages";
        case ETH_P_LINK_CTL:
            return "HPNA, wlan link local tunnel";
        case ETH_P_ATMFATE:
            return "Frame-based ATM Transport over Ethernet";
        case ETH_P_PAE:
            return "Port Access Entity [IEEE 802.1X]";
        case ETH_P_AOE:
            return "ATA over Ethernet";
        case ETH_P_8021AD:
            return "802.1ad Service VLAN";
        case ETH_P_802_EX1:
            return "802.1 Local Experimental 1.";
        case ETH_P_PREAUTH:
            return "802.11 Preauthentication";
        case ETH_P_TIPC:
            return "TIPC";
        case ETH_P_LLDP:
            return "Link Layer Discovery Protocol";
        case ETH_P_MRP:
            return "Media Redundancy Protocol";
        case ETH_P_MACSEC:
            return "802.1ae MACsec";
        case ETH_P_8021AH:
            return "802.1ah Backbone Service Tag";
        case ETH_P_MVRP:
            return "802.1Q MVRP";
        case ETH_P_1588:
            return "IEEE 1588 Timesync";
        case ETH_P_NCSI:
            return "NCSI protocol";
        case ETH_P_PRP:
            return "IEC 62439-3 PRPHSRv0";
        case ETH_P_CFM:
            return "Connectivity Fault Management";
        case ETH_P_FCOE:
            return "Fibre Channel over Ethernet";
        case ETH_P_IBOE:
            return "Infiniband over Ethernet";
        case ETH_P_TDLS:
            return "TDLS";
        case ETH_P_FIP:
            return "FCoE Initialization Protocol";
        case ETH_P_80221:
            return "IEEE 802.21 Media Independent Handover Protocol";
        case ETH_P_HSR:
            return "IEC 62439-3 HSRv1";
        case ETH_P_NSH:
            return "Network Service Header";
        case ETH_P_LOOPBACK:
            return "Ethernet loopback packet, per IEEE 802.3";
        case ETH_P_QINQ1:
            return "deprecated QinQ VLAN";
        case ETH_P_QINQ2:
            return "deprecated QinQ VLAN";
        case ETH_P_QINQ3:
            return "deprecated QinQ VLAN";
        case ETH_P_EDSA:
            return "Ethertype DSA";
        case ETH_P_DSA_8021Q:
            return "Fake VLAN Header for DSA";
        case ETH_P_IFE:
            return "ForCES inter-FE LFB type";
        case ETH_P_AF_IUCV:
            return "IBM af_iucv";
        default:
            return "Unknown";
    }
}

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
            return "TTL Expired";
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
    fprintf(fd,"%s",mesg);
    int i,j;
    for(i=0 ; i < len ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(fd,"    "); // Spaces in between
			for(j=i-16 ; j<i ; j++)
			{
				if(p[j]>=32 && p[j]<=128)
					fprintf(fd,"%c",(unsigned char)p[j]); //if its a number or alphabet
				
				else fprintf(fd,"."); //otherwise print a dot
			}
			fprintf(fd,"\n");
		} 

    	//if(i%16==0) fprintf(fd,""); // Prepending Spaces
		fprintf(fd," %02X",(unsigned int)p[i]);
				
		if( i==len-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(fd,"   "); //extra spaces
			
			fprintf(fd,"    ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(p[j]>=32 && p[j]<=128) fprintf(fd,"%c",(unsigned char)p[j]);
				else fprintf(fd,".");
			}
			fprintf(fd,"\n");
		}
	}
}

// Invalid Packets
void INVALID_CAPTURE(char *proto, FILE *log, FILE *stream)
{
    fprintf(log,"|- Could Not Capture Full %s Packet\n",proto);
    fprintf(stream,RED("|-")" Could Not Capture Full "RED("%s")" Packet\n",proto);
}
