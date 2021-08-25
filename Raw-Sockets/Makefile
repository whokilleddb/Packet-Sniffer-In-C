# Compiler : GCC 
CC = gcc

# HEADER Files
HEADERS = src/headers

# Global Files
GLOBALS = src/globals

# Compiler Flags:
# -O2 : Optimazation level
# -Wall : Print All Warnings 
# -Werror : Convert All Warnings Into Errors
# -g : Add Debugging Symbols
# -I : Directory containing headers
# -pipe : Avoid temporary files, speeding up builds
# -Os : Optimize Size
CFLAGS =  -Wall -Werror -g -O2 -I $(HEADERS) -I $(GLOBALS) -pipe -Os

# Build Target Executable
TARGET = sniffer

# Target Directory
DIR = src/main

all: $(TARGET)

$(TARGET): $(DIR)/$(TARGET).c
	$(CC)  $(DIR)/$(TARGET).c $(CFLAGS) -o sniffer

clean:
	$(RM) sniffer