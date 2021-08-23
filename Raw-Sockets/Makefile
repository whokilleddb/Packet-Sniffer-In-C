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

# Target Directory
DIR = src/main

all: $(TARGET)

$(TARGET): $(DIR)/$(TARGET).c
	$(CC)  $(DIR)/$(TARGET).c $(CFLAGS) -o sniffer

clean:
	$(RM) sniffer