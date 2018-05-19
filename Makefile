# Author: Maleakhi Agung Wijaya (maleakhiw)
# Student ID: 784091
# Makefile for COMP30023 Assignment 2

# Constant
CC = gcc
CFLAGS = -lssl -lcrypto

# Default if user type 'make'
default: certcheck

certcheck: certcheck.c
	$(CC) -Wall -o certcheck certcheck.c $(CFLAGS)

# To clean the executable and object file
clean:
	-rm -f certcheck
