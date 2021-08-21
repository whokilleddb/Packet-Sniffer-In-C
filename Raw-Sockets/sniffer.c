/* Packet Sniffer Using Raw Sockets
   The program can however only sniff incoming packets 
   THe resulting executable must be run as root to sniff packets

   Coded by @whokilleddb
*/
#include <netinet/in.h>
#include "modules.h"

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		fprintf(stderr,"[-] "RED("Incorrect Syntax") "\n[+] " YELLOW("Usage") " : %s [interface]\n",argv[0]);
		GET_INTERFACES();
		exit(EXIT_FAILURE);
	}

	//int saddr_size , data_size;
	//struct sockaddr saddr;
	//struct in_addr in;

	unsigned char *buffer = (unsigned char *)malloc(MTU);
	memset(buffer,0,MTU);
	


	free(buffer);
	return 0;
}