# Author: Maleakhi Agung Wijaya (maleakhiw)
# Student ID: 784091
# Makefile for COMP30023 Assignment 2

# Constant
CC = gcc
CFLAGS = -lssl -lcrypto
MAIN = certcheck

# Default if user type 'make' (call certcheck)
default: $(MAIN)

# Create certcheck executable
$(MAIN): certcheck.c certvalidation.o
	$(CC) -Wall -o $(MAIN) certcheck.c certvalidation.o $(CFLAGS)

# Create object file for certvalidation
certvalidation.o: certvalidation.c certvalidation.h
	$(CC) -c certvalidation.c

# To clean the executable and object file
clean:
	-rm -f *.o
	-rm -f certcheck
