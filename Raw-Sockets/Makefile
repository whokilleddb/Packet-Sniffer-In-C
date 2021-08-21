# Compiler : GCC 
CC = gcc

# Compiler Flags:
# -lcurl : Link Against libcurl
# -O2 : Optimazation level
# -Wall : Print All Warnings 
# -Werror : Convert All Warnings Into Errors
# -g : Add Debugging Symbols
CFLAGS =  -Wall -Werror -g -O2 

# Build Target Executable
TARGET = sniffer


all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC)  $(TARGET).c $(CFLAGS) -o sniffer

clean:
	$(RM) sniffer