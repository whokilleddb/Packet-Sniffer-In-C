#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <linux/ip.h>
#include <netinet/in.h>

int CreateRawSocket(int protocol_to_sniff)
{
	int rawsocket;
	if((rawsocket=socket(PF_PACKET, SOCK_RAW,htons(protocol_to_sniff)))==-1)
	{
		perror("Error Creating Socket");
		exit(-2);
	}
	return rawsocket;
}

int BindRawSocketToInterface(char *device, int rawsock,int protocol)
{
	struct sockaddr_ll sll;
	struct ifreq ifr; // Stores Information About The Interface To Sniff On

	bzero(&sll,sizeof(sll));
	bzero(&ifr,sizeof(ifr));

/* struct ifreq {
               char ifr_name[IFNAMSIZ]; // Interface Name
               union {
                   struct sockaddr ifr_addr;
                   struct sockaddr ifr_dstaddr;
                   struct sockaddr ifr_broadaddr;
                   struct sockaddr ifr_netmask;
                   struct sockaddr ifr_hwaddr;
                   short           ifr_flags;
                   int             ifr_ifindex;
                   int             ifr_metric;
                   int             ifr_mtu;
                   struct ifmap    ifr_map;
                   char            ifr_slave[IFNAMSIZ];
                   char            ifr_newname[IFNAMSIZ];
                   char           *ifr_data;
               };
           };

*/
	/* Copy Device Name To ifr */
	strncpy((char *)ifr.ifr_name, device,IFNAMSIZ);

	if((ioctl(rawsock,SIOCGIFINDEX,&ifr))==-1)//Gets us the interface number of our device
	{
		perror("[-] Error Getting Interface Name!\n");
		exit(-3);
	}

	/* Bind Socket To Interface */
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex=ifr.ifr_ifindex;
	sll.sll_protocol=htons(protocol);

	if (( bind(rawsock,( struct  sockaddr *)&sll, sizeof(sll) ))==-1 )
	{
		perror("[-] Cannot Bind Socket To Interface \n");
		exit(-4);
	}

	return 0;
}

int PrintPacketInHex(unsigned char *packet,int len)
{
	unsigned char *p =packet;
	printf("\n\n-----------------Packet Begins-----------------\n\n");
	while(len --)
	{
		printf("%.2x",*p);
		p++;
	}

	printf("\n\n------------------Packet Ends------------------\n");
}

int PrintInHex(char *mesg, unsigned char *p, int len)
{
	printf(mesg);
	while(len--)
	{
		printf("%.2X ",*p);
		p++;
	}
}

int ParseEthernetHeader(unsigned char *packet,int len)
{
	struct ethhdr *ethernet_header;

	if(len>sizeof(struct ethhdr))
	{
		ethernet_header=(struct ethhdr *)packet;
		PrintInHex("[+] Destination MAC : ", ethernet_header-> h_dest,6);
		printf("\n");

		PrintInHex("[+] Source MAC : ", ethernet_header-> h_source,6);
		printf("\n");

		PrintInHex("[+] Protocol : ", (void *)&ethernet_header-> h_proto,2);
		printf("\n");




	}
	/* First 6 Bytes Are Destination  MAC */
}

int ParseIPHeader(unsigned char *packet,int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	
/*	struct iphdr {
		#if defined(__LITTLE_ENDIAN_BITFIELD)
		        __u8    ihl:4,
		                version:4;
		#elif defined (__BIG_ENDIAN_BITFIELD)
		        __u8    version:4,
		                ihl:4;
		#else
		#error  "Please fix <asm/byteorder.h>"
		#endif
		        __u8    tos;
		        __be16  tot_len;
		        __be16  id;
		        __be16  frag_off;
		        __u8    ttl;
		        __u8    protocol;
		        __sum16 check;
		        __be32  saddr;
		        __be32  daddr;
		        //The options start here.
		};
*/
	ethernet_header=(struct ethhdr *)packet;

	if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
	{
		if(len >= (sizeof(struct ethhdr)+sizeof(struct iphdr)) )
		{
			ip_header=(struct iphdr*)(packet + sizeof(struct ethhdr));
			struct in_addr dest,source;
			dest.s_addr = ip_header->daddr;
			source.s_addr = ip_header->saddr;
			
			printf("[+] Destination IP : %s\n", inet_ntoa(dest));
			printf("[+] Source IP : %s\n",inet_ntoa(source));
			printf("[+] TTL : %d \n",ip_header->ttl);
		}
		else
		{
			printf("Full IP Header not found\n");
		}
	}

}


int main(int argc, char **argv)
{

	if(argc!=3)
	{
		perror("[-] Wrong Usage\n");
		exit(-99);
	}
	int raw;
	unsigned char packet_buffer[2048];
	int len;
	int packets_to_sniff;
	struct sockaddr_ll packet_info;
	int packet_info_size=sizeof(packet_info);

	/* Create A Raw Socket */	
	raw = CreateRawSocket(ETH_P_IP);

	/* Bind Socket To An Interface */
	BindRawSocketToInterface(argv[1],raw,ETH_P_IP);

	/* Get Number Of Packets To Sniff From User */
	packets_to_sniff=atoi(argv[2]);

	/* Start Sniffing And Print Hex Values */
	while(packets_to_sniff--)
	{
		if((len=recvfrom(raw,packet_buffer,2048,0,(struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("[-] Function recvfrom() returned exit status -1\n");
			exit(-1);
		}
		
		else
		{
			/* Packet Received */
			PrintPacketInHex(packet_buffer, len);
			ParseEthernetHeader(packet_buffer, len);
			ParseIPHeader(packet_buffer, len);
		}
		
	}

	return 0;
}
