#include <stdio.h>	
#include <stdlib.h>	

// Print Colors
#define RED(string)     "\x1b[31m" string "\x1b[0m"
#define GREEN(string)   "\x1b[32m" string "\x1b[0m"
#define YELLOW(string)  "\x1b[33m" string "\x1b[0m"
#define BLUE(string)    "\x1b[34m" string "\x1b[0m"
#define MAGENTA(string) "\x1b[35m" string "\x1b[0m"
#define CYAN(string)    "\x1b[36m" string "\x1b[0m"

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