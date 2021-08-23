/* Packet Sniffer Using Raw Sockets
   The program can however only sniff incoming packets 
   THe resulting executable must be run as root to sniff packets

   Coded by @whokilleddb
*/

#include "../headers/packetinfo.h"

int main(int argc, char *argv[])
{
	signal(SIGINT, SIGNINT_HANDLER);
	fprintf(stdout,"[" GREEN("+") "] " CYAN("Packet Sniffer") " by " MAGENTA("@whokilleddb")"\n");

	if(argc != 2)
	{
		fprintf(stderr,"["RED("-")"] "RED("Incorrect Syntax") "\n[+] " YELLOW("Usage") " : %s [interface]\n",argv[0]);
		GET_INTERFACES();
		exit(EXIT_FAILURE);
	}

	// Initialize Raw Socket 
	INIT_SOCKET();

	// Get Index Of The Interface
	INIT_INTERFACE(argv[1]);

	// Bind Socket
	BIND_SOCKET();

	// Initialise Log File
	INIT_LOGS();
	fprintf(logfile,"[+] Packet Sniffer In C by @whokilleddb\n");

	// Variables To Be Used 
	struct sockaddr_ll packet_info;
	socklen_t packet_len = sizeof(struct sockaddr_ll);

	// Buffer To Store The Input
	buffer = (unsigned char *)malloc(65536);
	if (buffer==NULL)
	{
		fprintf(stderr,"[" RED("-") "] " RED("malloc") " Failed\n");;
	}

	while(1)
	{
		memset(buffer,0,65536);
		ssize_t len;
		if((len=recvfrom(sock_raw,buffer,MTU,0,(struct sockaddr*)&packet_info, &packet_len)) == -1)
		{
			fprintf(stderr,"["RED("-")"] Function" RED("recvfrom()") " Errored Out\n");
		}
		else
		{
			PRINT_PACKET_INFO(buffer,len);
		}		
	}

	CLEANUP();
	return 0;
}