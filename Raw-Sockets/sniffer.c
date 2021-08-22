/* Packet Sniffer Using Raw Sockets
   The program can however only sniff incoming packets 
   THe resulting executable must be run as root to sniff packets

   Coded by @whokilleddb
*/
#include <netinet/in.h>
#include "modules.h"

int main(int argc, char *argv[])
{
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

	// Initialise Log File
	INIT_LOGS();

	// Variables To Be Used 
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct sockaddr_ll packet_info;
	int packet_len = sizeof(struct sockaddr_ll);

	// Buffer To Store The Input
	buffer = (unsigned char *)malloc(65536);
	if (buffer==NULL)
	{
		fprintf(stderr,"[" RED("-") "] " RED("malloc") " Failed\n");;
	}
	
	

	int i=0;
	while(i<100)
	{
		memset(buffer,0,65536);
		
	}

	CLEANUP();
	return 0;
}