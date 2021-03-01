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
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#define MTU 65536

int PrintInHex(char *mesg, unsigned char *p, int len)
{
        printf(mesg);
        while(len--)
        {
                printf("%.2X ",*p);
                p++;
        }
}


int PrintPacketInfo(unsigned char *packet,int len)
{
        struct ethhdr *ethernet_header;
		struct iphdr *ip_header;
		struct tcphdr *tcp_header;
        struct udphdr *udp_header;
        unsigned char *data;
        long int data_len;


        if(len>sizeof(struct ethhdr))
        {
                ethernet_header=(struct ethhdr *)packet;
                PrintInHex("[+] Destination MAC : ", ethernet_header-> h_dest,6);
                printf("\n");

                PrintInHex("[+] Source MAC : ", ethernet_header-> h_source,6);
                printf("\n");

                PrintInHex("[+] Protocol : ", (void *)&ethernet_header-> h_proto,2);
                printf("\n\n");

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
	                        printf("[+] TTL : %d \n\n",ip_header->ttl);

	                        if((len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr))) && (ip_header->protocol==IPPROTO_TCP))
	                        {
       	                        tcp_header=(struct tcphdr*)(packet + sizeof(struct ethhdr)+ip_header->ihl*4);
       	                        printf("[+] TCP Connection !\n");
       	                        printf("[+] Source Port : %d\n",ntohs(tcp_header-> source));
       	                        printf("[+] Dest Port : %d\n",ntohs(tcp_header-> dest));

								printf("[+] Syn Flag : %d\n",tcp_header->syn);
								printf("[+] Ack Flag : %d\n",tcp_header->ack);
								printf("[+] Fin Flag : %d\n\n",tcp_header->fin);
									                        
       	                        data=( packet+sizeof(struct ethhdr)+ip_header->ihl*4+sizeof(struct tcphdr) );
       	                        data_len=ntohs(ip_header->tot_len)-ip_header->ihl*4-sizeof(struct tcphdr);

       	                        if(data_len)
       	                        {
       	                        	printf("[+] Data Length %d\n",data_len);
       	                        	PrintInHex("[+] Data : ",data,data_len);
       	                        	return 0;
       	                        }
       	                    }

	                        else if((len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr))) && (ip_header->protocol==IPPROTO_UDP))       	
   	                        {
       	                                printf("[+] UDP Connection !\n");
       	                                udp_header=(struct udphdr*)(packet + sizeof(struct ethhdr)+ip_header->ihl*4);
       	                                printf("[+] Source Port : %d\n",ntohs(udp_header-> source));
       	                                printf("[+] Dest Port : %d\n",ntohs(udp_header-> dest));
       	                                data=(packet+sizeof(struct ethhdr)+ip_header->ihl*4+sizeof(struct udphdr));
       	                        		data_len=ntohs(ip_header->tot_len)-ip_header->ihl*4-sizeof(struct udphdr);
       	                        		if(data_len)
       	                        		{
       	                        			printf("[+] Data Length %d\n",data_len);
       	                        			PrintInHex("[+] Data : ",data,data_len);
       	                        			return 0;
       	                        		}
   	                        }
   	                        
   	                        else
   	                        {
   	                                printf("[-] Not a TCP/UDP PACKET\n");
   	                                return -3;
   	                        }
	                        
	                }
	                
	                else
	                {
	                        printf("Full IP Header not found\n");
	                        return -2;
	                }
        		}

		}
		
		else
		{
			printf("[-] Full Ethernet Header Could Not Be Captured :(\n");
			return -1;
		}
}

void main(int argc, char *argv[])
{
	if(argc != 2)
	{
		perror("[-] Incorrect Syntax\n[+] Usage : ./sniffer [interface]\n");
		exit(-1);
	}

	int raw; // Store Socket File Descriptor
	unsigned char packet_buffer[MTU];
	int len;
	struct sockaddr_ll packet_info, sll;
	int packet_info_size=sizeof(struct sockaddr_ll);	
    struct ifreq ifr; // Stores Information About The Interface To Sniff On

	printf("[+] PACKET SNIFFER IN C ! CODED BY @whokilleddb\n\n");

	//Create A Raw Socket;
	if((raw=socket(PF_PACKET, SOCK_RAW,htons(ETH_P_IP)))==-1) // Return Socket File Descriptor
    {
		perror("[-] Error Creating Socket\n");
		exit(-2);
	}
	printf("[+] Successfully Created Raw Socket \n");

	// Bind Socket To Interface
	memset(&sll,0,sizeof(sll));
	memset(&ifr,0,sizeof(sll));

	// Copy Device Name To ifr
	strncpy((char *)ifr.ifr_name,argv[1],IFNAMSIZ);
	if((ioctl(raw,SIOCGIFINDEX,&ifr))==-1)//Gets us the interface number of our device
	{
		perror("[-] Error Getting Interface Name!\n");
		exit(-3);
	}

	// Bind Socket To Interface
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex=ifr.ifr_ifindex;
	sll.sll_protocol=htons(ETH_P_IP);

	if (( bind(raw,(struct  sockaddr *)&sll, sizeof(sll)))==-1 )
	{
	        perror("[-] Cannot Bind Socket To Interface \n");
	        exit(-4);
	}
	printf("[+] Successfully Bounded Raw Socket To %s\n",argv[1]);

	while(1)
	{
		if((len=recvfrom(raw,packet_buffer,sizeof(packet_buffer),0,(struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("[-] Function recvfrom() returned exit status -1\n");
			exit(-1);	
		}	
		else
		{
			printf("\n\n-----------------Packet Begins-----------------\n\n");
			PrintPacketInfo(packet_buffer, len);
			printf("\n\n------------------Packet Ends------------------\n");
			
		}
	}

}
